use crate::codemode_limits::limits;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use rquickjs::{
    convert::List, function::Func, CatchResultExt, CaughtError, CaughtResult, Context as JsContext,
    Ctx, Exception, Promise, Runtime, String as JsString, TypedArray,
};
use serde_json::Value;

use super::codemode_protocol::{
    bounded_failure_message, encode_frame, ConnectorCallResult, ConsoleCapture, ConsoleLevel,
    ParentFrame, RunnerBinding, RunnerFailureCode, RunnerFrame, RunnerResumeContext,
    CONFINEMENT_PROFILE, RUNNER_SPOOL_FLAG,
};

/// Budget applied when no parent frame has narrowed it. Sourced from the
/// protocol default so the parent and the runner cannot disagree about
/// what "unspecified" means.
const EXECUTION_LIMIT: Duration =
    Duration::from_millis(super::codemode_protocol::default_execution_limit_ms());
const RESULT_ENVELOPE_OVERHEAD_BYTES: usize = r#"{"result":}"#.len();
const CONNECTOR_MATERIALIZATION_FAILURE: &str =
    "gateway connector result exceeded runtime materialization capacity";
/// Closes the async function a program body runs in, then serializes the value
/// the program settled to with intrinsics captured before the program ran.
const PROGRAM_EPILOGUE: &str = r#"
  })();
  const gatewayResultEnvelope = gatewayObjectCreate(null);
  gatewayDefineProperty(gatewayResultEnvelope, "result", {
    value: gatewayProgramResult,
    enumerable: true
  });
  try {
    return gatewayJsonStringify(gatewayResultEnvelope);
  } catch {
    return "{}";
  }
})();
"#;
/// Installs the global `console`. Each call is formatted here, close to
/// Node.js's `util.format`, and handed to the host as one line of text. The
/// formatter stops once a call's text passes the console budget, so printing a
/// huge value costs no more than the output that can be kept. Every method
/// swallows its own failures: debugging output must never end a program.
const CONSOLE_PRELUDE: &str = r#"
Object.defineProperty(globalThis, "console", {
  value: (() => {
    const gatewayConsole = __gateway_console;
    const textLimit = __gateway_console_bytes;
    const programStack = __gateway_program_stack;
    delete globalThis.__gateway_console;
    delete globalThis.__gateway_console_bytes;
    delete globalThis.__gateway_program_stack;
    const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed);
    const full = Symbol("console output limit");
    const render = (args) => {
      const parts = [];
      let length = 0;
      // Every piece is cut to the room left before it is kept, so the
      // joined text never passes the budget by more than one character.
      const room = () => textLimit - length;
      const push = (text) => {
        if (text.length > room()) {
          parts.push(text.slice(0, room() + 1));
          length = textLimit + 1;
          throw full;
        }
        parts.push(text);
        length += text.length;
      };
      const quote = (text) => JSON.stringify(text.length > room() ? text.slice(0, room() + 1) : text);
      const inspect = (value, nested, seen) => {
        switch (typeof value) {
          case "string":
            push(nested ? quote(value) : value);
            return;
          case "bigint":
            push(`${value}n`);
            return;
          case "symbol":
            push(value.toString());
            return;
          case "function":
            push(`[Function: ${value.name || "anonymous"}]`);
            return;
          case "object":
            break;
          default:
            push(Object.is(value, -0) ? "-0" : String(value));
            return;
        }
        if (value === null) {
          push("null");
          return;
        }
        if (seen.includes(value)) {
          push("[Circular]");
          return;
        }
        if (seen.length >= 8) {
          push(Array.isArray(value) ? "[Array]" : "[Object]");
          return;
        }
        seen.push(value);
        try {
          if (value instanceof Error) {
            push(`${value.name}: ${value.message}`);
            if (typeof value.stack === "string" && value.stack !== "") {
              push(`\n${programStack(value.stack.replace(/\n+$/, ""))}`);
            }
          } else if (Array.isArray(value)) {
            push("[");
            for (let index = 0; index < value.length; index += 1) {
              if (index > 0) push(", ");
              inspect(value[index], true, seen);
            }
            push("]");
          } else if (value instanceof Map || value instanceof Set) {
            push(`${value instanceof Map ? "Map" : "Set"}(${value.size}) {`);
            let first = true;
            for (const entry of value) {
              if (!first) push(", ");
              first = false;
              if (value instanceof Map) {
                inspect(entry[0], true, seen);
                push(" => ");
                inspect(entry[1], true, seen);
              } else {
                inspect(entry, true, seen);
              }
            }
            push("}");
          } else if (value instanceof Date) {
            push(Number.isNaN(value.getTime()) ? "Invalid Date" : value.toISOString());
          } else if (value instanceof RegExp) {
            push(String(value));
          } else if (value instanceof ArrayBuffer) {
            push(`ArrayBuffer { byteLength: ${value.byteLength} }`);
          } else if (value instanceof DataView) {
            push(`DataView { byteLength: ${value.byteLength} }`);
          } else if (ArrayBuffer.isView(value)) {
            push(`${value.constructor.name}(${value.length}) [`);
            for (let index = 0; index < value.length; index += 1) {
              if (index > 0) push(", ");
              push(String(value[index]));
            }
            push("]");
          } else if (value instanceof Promise) {
            push("Promise {}");
          } else if (typeof value.toJSON === "function") {
            inspect(value.toJSON(), nested, seen);
          } else {
            push("{");
            let first = true;
            for (const key of Object.keys(value)) {
              if (!first) push(", ");
              first = false;
              push(`${quote(key)}: `);
              inspect(value[key], true, seen);
            }
            push("}");
          }
        } finally {
          seen.pop();
        }
      };
      const substitute = (spec, arg) => {
        switch (spec) {
          case "s":
            if (typeof arg === "bigint") push(`${arg}n`);
            else if (typeof arg === "object" && arg !== null) inspect(arg, true, []);
            else push(String(arg));
            return;
          case "d":
          case "i":
          case "f":
            if (typeof arg === "bigint") push(`${arg}n`);
            else if (typeof arg === "symbol") push("NaN");
            else if (spec === "d") push(String(Number(arg)));
            else if (spec === "i") push(String(parseInt(arg, 10)));
            else push(String(parseFloat(arg)));
            return;
          case "j": {
            // The replacer stops serialization once its running size passes
            // the budget; the bounded formatter then prints what fits.
            let size = 0;
            let text;
            try {
              text = JSON.stringify(arg, (key, item) => {
                size += key.length + (typeof item === "string" ? item.length : 8);
                if (size > room()) throw full;
                return item;
              });
            } catch (error) {
              if (error === full) {
                inspect(arg, true, []);
              } else {
                push(/circular/i.test(String(error?.message)) ? "[Circular]" : "[could not serialize]");
              }
              return;
            }
            push(String(text));
            return;
          }
          case "o":
          case "O":
            inspect(arg, true, []);
            return;
          default:
            return;
        }
      };
      try {
        let next = 0;
        if (typeof args[0] === "string" && args.length > 1) {
          const template = args[0];
          next = 1;
          let literal = "";
          for (let index = 0; index < template.length; index += 1) {
            const spec = template[index + 1];
            if (template[index] === "%" && spec === "%") {
              literal += "%";
              index += 1;
            } else if (template[index] === "%" && spec !== undefined && "sdifjoOc".includes(spec) && next < args.length) {
              push(literal);
              literal = "";
              substitute(spec, args[next]);
              next += 1;
              index += 1;
            } else {
              literal += template[index];
            }
            if (literal.length > room()) push(literal);
          }
          push(literal);
        }
        for (let index = next; index < args.length; index += 1) {
          if (index > 0) push(" ");
          inspect(args[index], false, []);
        }
      } catch (error) {
        if (error !== full) {
          // The note is budgeted like any other text, in pieces, so a huge
          // message is never copied in full.
          try {
            push(" [console could not format a value: ");
            push(error instanceof Error ? String(error.message) : typeof error);
            push("]");
          } catch {
            // The budget ran out while noting the failure.
          }
        }
      }
      return parts.join("");
    };
    let depth = 0;
    // Group indentation is charged against the same budget as the text.
    const indentLines = (text) => {
      const indent = "  ".repeat(Math.min(depth, Math.ceil(textLimit / 2)));
      const lines = [];
      let size = 0;
      for (const line of text.split("\n")) {
        const indented = indent + line;
        if (size + indented.length > textLimit) {
          lines.push(indented.slice(0, Math.max(0, textLimit - size + 1)));
          break;
        }
        lines.push(indented);
        size += indented.length + 1;
      }
      return lines.join("\n");
    };
    const emit = (level, args, suffix = "", prefix = "") => {
      try {
        let text = prefix + render(args) + suffix;
        if (depth > 0) text = indentLines(text);
        gatewayConsole(level, wellFormed(text));
      } catch {
        // Output that cannot be formatted or delivered is dropped.
      }
    };
    const counts = new Map();
    const timers = new Map();
    const label = (name) => (name === undefined ? "default" : String(name));
    const elapsed = (start) => `${(performance.now() - start).toFixed(3)}ms`;
    const methods = {
      log: (...args) => emit("log", args),
      info: (...args) => emit("info", args),
      debug: (...args) => emit("debug", args),
      warn: (...args) => emit("warn", args),
      error: (...args) => emit("error", args),
      trace: (...args) => {
        const stack = programStack((new Error().stack ?? "").replace(/\n+$/, ""));
        emit("error", args, `\n${stack}`, args.length > 0 ? "Trace: " : "Trace");
      },
      dir: (value) => emit("log", [value]),
      dirxml: (...args) => emit("log", args),
      table: (data) => emit("log", [data]),
      assert: (condition, ...args) => {
        if (condition) return;
        if (args.length === 0) emit("error", ["Assertion failed"]);
        else if (typeof args[0] === "string") emit("error", [`Assertion failed: ${args[0]}`, ...args.slice(1)]);
        else emit("error", ["Assertion failed:", ...args]);
      },
      count: (name) => {
        const key = label(name);
        const total = (counts.get(key) ?? 0) + 1;
        counts.set(key, total);
        emit("log", [`${key}: ${total}`]);
      },
      countReset: (name) => {
        counts.delete(label(name));
      },
      group: (...args) => {
        if (args.length > 0) emit("log", args);
        depth += 1;
      },
      groupCollapsed: (...args) => {
        if (args.length > 0) emit("log", args);
        depth += 1;
      },
      groupEnd: () => {
        if (depth > 0) depth -= 1;
      },
      time: (name) => {
        const key = label(name);
        if (timers.has(key)) {
          emit("warn", [`Timer "${key}" already exists`]);
          return;
        }
        timers.set(key, performance.now());
      },
      timeLog: (name, ...args) => {
        const key = label(name);
        const start = timers.get(key);
        if (start === undefined) emit("warn", [`Timer "${key}" does not exist`]);
        else emit("log", [`${key}: ${elapsed(start)}`, ...args]);
      },
      timeEnd: (name) => {
        const key = label(name);
        const start = timers.get(key);
        if (start === undefined) {
          emit("warn", [`Timer "${key}" does not exist`]);
          return;
        }
        timers.delete(key);
        emit("log", [`${key}: ${elapsed(start)}`]);
      },
    };
    // A method that fails, for example on a label that cannot become text,
    // drops its output rather than ending the program.
    for (const name of Object.keys(methods)) {
      const method = methods[name];
      methods[name] = (...args) => {
        try {
          method(...args);
        } catch {
          // Debugging output must never end a program.
        }
      };
    }
    return methods;
  })(),
  writable: true,
  enumerable: false,
  configurable: true
});
"#;
/// Installs `TextEncoder`, `TextDecoder`, `crypto.getRandomValues`,
/// `crypto.randomUUID` and `structuredClone`, following the web standards for
/// the parts this runtime supports. UTF-8 is the only encoding: any other
/// label is refused rather than decoded differently. Decoding, encoding and
/// randomness come from the host; they compute and never reach outside the
/// runner.
const STANDARD_HELPERS_PRELUDE: &str = r#"
(() => {
  const utf8Decode = __gateway_utf8_decode;
  const utf8Encode = __gateway_utf8_encode;
  const randomBytes = __gateway_random_bytes;
  const engineClass = __gateway_engine_class;
  delete globalThis.__gateway_utf8_decode;
  delete globalThis.__gateway_utf8_encode;
  delete globalThis.__gateway_random_bytes;
  delete globalThis.__gateway_engine_class;
  const define = (name, value) => Object.defineProperty(globalThis, name, {
    value,
    writable: true,
    enumerable: false,
    configurable: true
  });
  const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed);
  // Built-ins captured before the program runs, called with the value as
  // receiver, so a value's own properties cannot stand in for them.
  const method = (prototype, name) => Function.prototype.call.bind(prototype[name]);
  const getter = (prototype, name) =>
    Function.prototype.call.bind(Object.getOwnPropertyDescriptor(prototype, name).get);
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  const typedArrayName = getter(typedArrayPrototype, Symbol.toStringTag);
  const viewBuffer = getter(typedArrayPrototype, "buffer");
  const viewOffset = getter(typedArrayPrototype, "byteOffset");
  const viewByteLength = getter(typedArrayPrototype, "byteLength");
  const viewLength = getter(typedArrayPrototype, "length");
  const dataViewBuffer = getter(DataView.prototype, "buffer");
  const dataViewOffset = getter(DataView.prototype, "byteOffset");
  const dataViewByteLength = getter(DataView.prototype, "byteLength");
  const bufferDetached = getter(ArrayBuffer.prototype, "detached");
  const bufferByteLength = getter(ArrayBuffer.prototype, "byteLength");
  const bufferResizable = getter(ArrayBuffer.prototype, "resizable");
  const bufferMaxByteLength = getter(ArrayBuffer.prototype, "maxByteLength");
  const bufferResize = method(ArrayBuffer.prototype, "resize");
  const bufferTransfer = method(ArrayBuffer.prototype, "transfer");
  const asciiWhitespace = /^[\t\n\f\r ]+|[\t\n\f\r ]+$/g;
  const utf8Labels = new Set([
    "unicode-1-1-utf-8", "unicode11utf8", "unicode20utf8", "utf-8", "utf8", "x-unicode20utf8"
  ]);
  const empty = () => new Uint8Array(0);
  const bytesOf = (input) => {
    if (input === undefined) return empty();
    if (input instanceof ArrayBuffer || input instanceof SharedArrayBuffer) return new Uint8Array(input);
    if (typedArrayName(input) !== undefined) {
      return new Uint8Array(viewBuffer(input), viewOffset(input), viewByteLength(input));
    }
    if (input instanceof DataView) {
      return new Uint8Array(dataViewBuffer(input), dataViewOffset(input), dataViewByteLength(input));
    }
    throw new TypeError("TextDecoder.decode expects an ArrayBuffer, a typed array or a DataView");
  };
  const tailOf = (first, second, length) => {
    const tail = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) {
      const position = first.length + second.length - length + index;
      tail[index] = position < first.length ? first[position] : second[position - first.length];
    }
    return tail;
  };

  class TextDecoder {
    #fatal;
    #ignoreBOM;
    #pending = empty();
    #bomChecked = false;
    constructor(label = "utf-8", options = undefined) {
      const normalized = String(label).replace(asciiWhitespace, "").toLowerCase();
      if (!utf8Labels.has(normalized)) {
        throw new RangeError(`The "${label}" encoding is not supported; this runtime decodes UTF-8 only`);
      }
      this.#fatal = Boolean(options?.fatal);
      this.#ignoreBOM = Boolean(options?.ignoreBOM);
    }
    get encoding() { return "utf-8"; }
    get fatal() { return this.#fatal; }
    get ignoreBOM() { return this.#ignoreBOM; }
    get [Symbol.toStringTag]() { return "TextDecoder"; }
    decode(input = undefined, options = undefined) {
      const stream = Boolean(options?.stream);
      const bytes = bytesOf(input);
      let decoded;
      try {
        decoded = utf8Decode(this.#pending, bytes, this.#fatal, stream);
      } catch (error) {
        this.#pending = empty();
        this.#bomChecked = false;
        throw error;
      }
      let text = decoded[0];
      if (!this.#bomChecked && text.length > 0) {
        this.#bomChecked = true;
        if (!this.#ignoreBOM && text.charCodeAt(0) === 0xfeff) text = text.slice(1);
      }
      if (stream) {
        this.#pending = tailOf(this.#pending, bytes, decoded[1]);
      } else {
        this.#pending = empty();
        this.#bomChecked = false;
      }
      return text;
    }
  }

  class TextEncoder {
    get encoding() { return "utf-8"; }
    get [Symbol.toStringTag]() { return "TextEncoder"; }
    encode(input = "") {
      return utf8Encode(wellFormed(String(input)));
    }
    encodeInto(source, destination) {
      if (typedArrayName(destination) !== "Uint8Array") {
        throw new TypeError("TextEncoder.encodeInto expects a Uint8Array destination");
      }
      const capacity = viewLength(destination);
      let read = 0;
      let written = 0;
      for (const character of wellFormed(String(source))) {
        const point = character.codePointAt(0);
        const size = point < 0x80 ? 1 : point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
        if (written + size > capacity) break;
        if (size === 1) {
          destination[written] = point;
        } else {
          let remaining = point;
          for (let index = size - 1; index > 0; index -= 1) {
            destination[written + index] = 0x80 | (remaining & 0x3f);
            remaining >>= 6;
          }
          destination[written] = [0, 0, 0xc0, 0xe0, 0xf0][size] | remaining;
        }
        written += size;
        read += character.length;
      }
      return { read, written };
    }
  }

  const integerArrays = {
    Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array, Int32Array, Uint32Array,
    BigInt64Array, BigUint64Array
  };
  const typedArrays = { ...integerArrays, Float16Array, Float32Array, Float64Array };
  const getRandomValues = (array) => {
    if (!Object.hasOwn(integerArrays, typedArrayName(array) ?? "")) {
      throw new DOMException("getRandomValues expects an integer typed array", "TypeMismatchError");
    }
    const length = viewByteLength(array);
    if (length > 65536) {
      throw new DOMException(
        `getRandomValues was asked for ${length} bytes; at most 65,536 are allowed`,
        "QuotaExceededError"
      );
    }
    new Uint8Array(viewBuffer(array), viewOffset(array), length).set(randomBytes(length));
    return array;
  };
  const randomUUID = () => {
    const bytes = randomBytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  };

  const dateTime = method(Date.prototype, "getTime");
  const regexpSource = getter(RegExp.prototype, "source");
  const regexpFlagReaders = [
    ["d", "hasIndices"], ["g", "global"], ["i", "ignoreCase"], ["m", "multiline"],
    ["s", "dotAll"], ["u", "unicode"], ["v", "unicodeSets"], ["y", "sticky"]
  ].flatMap(([flag, name]) => {
    const read = Object.getOwnPropertyDescriptor(RegExp.prototype, name)?.get;
    return read === undefined ? [] : [[flag, Function.prototype.call.bind(read)]];
  });
  const regexpFlags = (input) =>
    regexpFlagReaders.filter(([, read]) => read(input)).map(([flag]) => flag).join("");
  const mapEntries = method(Map.prototype, "entries");
  const setValues = method(Set.prototype, "values");
  const primitiveOf = {
    boolean: method(Boolean.prototype, "valueOf"),
    number: method(Number.prototype, "valueOf"),
    string: method(String.prototype, "valueOf"),
    bigint: method(BigInt.prototype, "valueOf")
  };
  // The engine class of each cloneable kind, learned from sample objects so
  // a value's type is judged by what it is rather than by its prototype.
  const kindOfClass = new Map();
  for (const [kind, sample] of [
    ["ordinary", {}], ["array", []], ["map", new Map()], ["set", new Set()], ["date", new Date(0)],
    ["regexp", /a/], ["arrayBuffer", new ArrayBuffer(0)], ["sharedArrayBuffer", new SharedArrayBuffer(0)],
    ["dataView", new DataView(new ArrayBuffer(0))], ["boolean", Object(false)], ["number", Object(0)],
    ["string", Object("")], ["bigint", Object(0n)], ["error", new Error()], ["domException", new DOMException()]
  ]) {
    const id = engineClass(sample);
    if (!kindOfClass.has(id)) kindOfClass.set(id, kind);
  }
  const describe = (value) => {
    try {
      return Object.prototype.toString.call(value);
    } catch {
      return "This value";
    }
  };
  // An empty buffer of the source's length, resizable to the same maximum
  // when the source is resizable.
  const bufferLike = (buffer) =>
    bufferResizable(buffer)
      ? new ArrayBuffer(bufferByteLength(buffer), { maxByteLength: bufferMaxByteLength(buffer) })
      : new ArrayBuffer(bufferByteLength(buffer));
  const copyBuffer = (buffer) => {
    const output = bufferLike(buffer);
    new Uint8Array(output).set(new Uint8Array(buffer));
    return output;
  };
  const errorTypes = { Error, EvalError, RangeError, ReferenceError, SyntaxError, TypeError, URIError };
  const uncloneable = (what) => new DOMException(`${what} could not be cloned`, "DataCloneError");
  const assign = (target, key, value) => Object.defineProperty(target, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true
  });
  const structuredClone = (value, options = undefined) => {
    const transfer = options?.transfer === undefined ? [] : Array.from(options.transfer);
    const transferred = new Set();
    for (const buffer of transfer) {
      if (kindOfClass.get(engineClass(buffer)) !== "arrayBuffer") {
        throw uncloneable("A transfer entry that is not an ArrayBuffer");
      }
      if (transferred.has(buffer)) throw uncloneable("An ArrayBuffer listed twice for transfer");
      if (bufferDetached(buffer)) throw uncloneable("A detached ArrayBuffer");
      transferred.add(buffer);
    }
    const memory = new Map();
    const pendingTransfers = [];
    const copy = (input) => {
      if (typeof input === "symbol") throw uncloneable(String(input));
      if (typeof input === "function") throw uncloneable(`The function ${input.name || "(anonymous)"}`);
      if (typeof input !== "object" || input === null) return input;
      if (memory.has(input)) return memory.get(input);
      // A proxy's target cannot be cloned through it, and the engine is the
      // only reliable judge of what is a proxy.
      const id = engineClass(input);
      if (id === -1) throw uncloneable("A Proxy");
      const typedName = typedArrayName(input);
      const kind = typedName === undefined ? kindOfClass.get(id) : "typedArray";
      const remember = (output) => {
        memory.set(input, output);
        return output;
      };
      switch (kind) {
        case "array": {
          const output = remember(new Array(input.length));
          for (const key of Object.keys(input)) {
            if (Object.hasOwn(input, key)) assign(output, key, copy(input[key]));
          }
          return output;
        }
        // Entries are listed before any is copied, as the standard does, so
        // a getter that changes the source cannot change the clone's members.
        case "map": {
          const output = remember(new Map());
          for (const [key, item] of Array.from(mapEntries(input))) output.set(copy(key), copy(item));
          return output;
        }
        case "set": {
          const output = remember(new Set());
          for (const item of Array.from(setValues(input))) output.add(copy(item));
          return output;
        }
        case "date":
          return remember(new Date(dateTime(input)));
        case "regexp":
          return remember(new RegExp(regexpSource(input), regexpFlags(input)));
        case "arrayBuffer": {
          if (bufferDetached(input)) throw uncloneable("A detached ArrayBuffer");
          if (!transferred.has(input)) return remember(copyBuffer(input));
          // A transferred buffer's bytes are taken after cloning finishes, so
          // writes made later during cloning are carried over.
          const output = remember(bufferLike(input));
          pendingTransfers.push([input, output]);
          return output;
        }
        case "sharedArrayBuffer":
          // Sharing memory needs a second agent, which this runtime never has.
          throw uncloneable("A SharedArrayBuffer");
        case "typedArray": {
          const buffer = copy(viewBuffer(input));
          return remember(new typedArrays[typedName](buffer, viewOffset(input), viewLength(input)));
        }
        case "dataView": {
          const buffer = copy(dataViewBuffer(input));
          return remember(new DataView(buffer, dataViewOffset(input), dataViewByteLength(input)));
        }
        case "boolean":
        case "number":
        case "string":
        case "bigint":
          return remember(Object(primitiveOf[kind](input)));
        case "domException":
          return remember(new DOMException(input.message, input.name));
        case "error": {
          if (input instanceof DOMException) return remember(new DOMException(input.message, input.name));
          // The standard copies `message` and `cause` only as own data
          // properties.
          const own = (key) => {
            const descriptor = Object.getOwnPropertyDescriptor(input, key);
            return descriptor !== undefined && "value" in descriptor ? descriptor : undefined;
          };
          const type = Object.hasOwn(errorTypes, input.name) ? errorTypes[input.name] : Error;
          const message = own("message");
          const output = remember(new type(message === undefined ? "" : String(message.value)));
          const stack = own("stack");
          if (typeof stack?.value === "string") {
            Object.defineProperty(output, "stack", { value: stack.value, writable: true, configurable: true });
          }
          const cause = own("cause");
          if (cause !== undefined) {
            Object.defineProperty(output, "cause", { value: copy(cause.value), writable: true, configurable: true });
          }
          return output;
        }
        case "ordinary": {
          // A captured key that a getter has since removed is skipped, as the
          // standard does.
          const output = remember({});
          for (const key of Object.keys(input)) {
            if (Object.hasOwn(input, key)) assign(output, key, copy(input[key]));
          }
          return output;
        }
        default:
          // Anything else carries engine state beyond its properties, such as
          // a promise, a weak collection, a generator or an iterator.
          throw uncloneable(describe(input));
      }
    };
    const result = copy(value);
    for (const buffer of transferred) {
      if (bufferDetached(buffer)) throw uncloneable("A detached ArrayBuffer");
    }
    for (const [original, output] of pendingTransfers) {
      if (bufferResizable(output)) bufferResize(output, bufferByteLength(original));
      const length = Math.min(bufferByteLength(original), bufferByteLength(output));
      new Uint8Array(output).set(new Uint8Array(original, 0, length));
    }
    // Detaching the originals completes the transfer; nothing is detached
    // when cloning fails.
    for (const buffer of transferred) bufferTransfer(buffer);
    return result;
  };

  define("TextDecoder", TextDecoder);
  define("TextEncoder", TextEncoder);
  define("crypto", { getRandomValues, randomUUID });
  define("structuredClone", structuredClone);
})();
"#;
/// Installs `URL` and `URLSearchParams`, following the URL Standard. The
/// host's parser is the workspace's WHATWG `url` crate; parsing only computes
/// a URL and never resolves or contacts it.
const URL_PRELUDE: &str = r#"
(() => {
  const parseUrl = __gateway_url_parse;
  // The host reports a failed parse as undefined.
  const parse = (input, base) => parseUrl(input, base) ?? null;
  const components = __gateway_url_components;
  const setComponent = __gateway_url_set;
  const formParse = __gateway_form_parse;
  const formSerialize = __gateway_form_serialize;
  delete globalThis.__gateway_url_parse;
  delete globalThis.__gateway_url_components;
  delete globalThis.__gateway_url_set;
  delete globalThis.__gateway_form_parse;
  delete globalThis.__gateway_form_serialize;
  const define = (name, value) => Object.defineProperty(globalThis, name, {
    value,
    writable: true,
    enumerable: false,
    configurable: true
  });
  const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed);
  const usv = (value) => wellFormed(String(value));
  const optional = (value) => (value === undefined ? null : usv(value));
  const states = new WeakMap();
  const state = (searchParams) => {
    const found = states.get(searchParams);
    if (found === undefined) throw new TypeError("Illegal invocation: not a URLSearchParams");
    return found;
  };
  const serialize = (list) => formSerialize(list.map((pair) => pair[0]), list.map((pair) => pair[1]));
  const changed = (current) => {
    if (current.update !== null) current.update(serialize(current.list));
  };

  class URLSearchParams {
    constructor(init = undefined) {
      const list = [];
      states.set(this, { list, update: null });
      if (init === undefined) return;
      if ((typeof init === "object" && init !== null) || typeof init === "function") {
        if (typeof init[Symbol.iterator] === "function") {
          for (const pair of init) {
            if (
              ((typeof pair !== "object" || pair === null) && typeof pair !== "function") ||
              typeof pair[Symbol.iterator] !== "function"
            ) {
              throw new TypeError("Each URLSearchParams pair must be an iterable object");
            }
            const items = Array.from(pair);
            if (items.length !== 2) {
              throw new TypeError("Each URLSearchParams pair must have exactly two items");
            }
            list.push([usv(items[0]), usv(items[1])]);
          }
        } else {
          for (const key of Object.keys(init)) list.push([usv(key), usv(init[key])]);
        }
        return;
      }
      const text = usv(init);
      for (const pair of formParse(text.startsWith("?") ? text.slice(1) : text)) list.push(pair);
    }
    get size() { return state(this).list.length; }
    get [Symbol.toStringTag]() { return "URLSearchParams"; }
    append(name, value) {
      const current = state(this);
      current.list.push([usv(name), usv(value)]);
      changed(current);
    }
    delete(name, value = undefined) {
      const current = state(this);
      const key = usv(name);
      const match = value === undefined ? null : usv(value);
      for (let index = current.list.length - 1; index >= 0; index -= 1) {
        const pair = current.list[index];
        if (pair[0] === key && (match === null || pair[1] === match)) current.list.splice(index, 1);
      }
      changed(current);
    }
    get(name) {
      const key = usv(name);
      const pair = state(this).list.find((candidate) => candidate[0] === key);
      return pair === undefined ? null : pair[1];
    }
    getAll(name) {
      const key = usv(name);
      return state(this).list.filter((pair) => pair[0] === key).map((pair) => pair[1]);
    }
    has(name, value = undefined) {
      const key = usv(name);
      const match = value === undefined ? null : usv(value);
      return state(this).list.some((pair) => pair[0] === key && (match === null || pair[1] === match));
    }
    set(name, value) {
      const current = state(this);
      const key = usv(name);
      const text = usv(value);
      const first = current.list.findIndex((pair) => pair[0] === key);
      if (first === -1) {
        current.list.push([key, text]);
      } else {
        current.list[first][1] = text;
        for (let index = current.list.length - 1; index > first; index -= 1) {
          if (current.list[index][0] === key) current.list.splice(index, 1);
        }
      }
      changed(current);
    }
    sort() {
      const current = state(this);
      current.list.sort((left, right) => (left[0] < right[0] ? -1 : left[0] > right[0] ? 1 : 0));
      changed(current);
    }
    forEach(callback, thisArg = undefined) {
      if (typeof callback !== "function") throw new TypeError("URLSearchParams.forEach expects a function");
      const list = state(this).list;
      for (let index = 0; index < list.length; index += 1) {
        callback.call(thisArg, list[index][1], list[index][0], this);
      }
    }
    *entries() {
      const list = state(this).list;
      for (let index = 0; index < list.length; index += 1) yield [list[index][0], list[index][1]];
    }
    *keys() {
      for (const pair of this.entries()) yield pair[0];
    }
    *values() {
      for (const pair of this.entries()) yield pair[1];
    }
    [Symbol.iterator]() { return this.entries(); }
    toString() { return serialize(state(this).list); }
  }

  const invalid = (input) => new TypeError(`Invalid URL: ${input}`);
  class URL {
    #href;
    #parts;
    #searchParams;
    static canParse(input, base = undefined) {
      return parse(usv(input), optional(base)) !== null;
    }
    static parse(input, base = undefined) {
      const href = parse(usv(input), optional(base));
      return href === null ? null : new URL(href);
    }
    constructor(input, base = undefined) {
      const text = usv(input);
      const href = parse(text, optional(base));
      if (href === null) throw invalid(text);
      this.#adopt(href);
      this.#searchParams = new URLSearchParams(this.#parts[8]);
      state(this.#searchParams).update = (query) => this.#adopt(setComponent(this.#href, "search", query));
    }
    #adopt(href) {
      this.#href = href;
      this.#parts = components(href);
    }
    #refreshParams() {
      const list = state(this.#searchParams).list;
      list.length = 0;
      for (const pair of formParse(this.#parts[8].slice(1))) list.push(pair);
    }
    #set(component, value) {
      this.#adopt(setComponent(this.#href, component, usv(value)));
    }
    get href() { return this.#href; }
    set href(value) {
      const text = usv(value);
      const href = parse(text, null);
      if (href === null) throw invalid(text);
      this.#adopt(href);
      this.#refreshParams();
    }
    get origin() { return this.#parts[0]; }
    get protocol() { return this.#parts[1]; }
    set protocol(value) { this.#set("protocol", value); }
    get username() { return this.#parts[2]; }
    set username(value) { this.#set("username", value); }
    get password() { return this.#parts[3]; }
    set password(value) { this.#set("password", value); }
    get host() { return this.#parts[4]; }
    set host(value) { this.#set("host", value); }
    get hostname() { return this.#parts[5]; }
    set hostname(value) { this.#set("hostname", value); }
    get port() { return this.#parts[6]; }
    set port(value) { this.#set("port", value); }
    get pathname() { return this.#parts[7]; }
    set pathname(value) { this.#set("pathname", value); }
    get search() { return this.#parts[8]; }
    set search(value) {
      this.#set("search", value);
      this.#refreshParams();
    }
    get hash() { return this.#parts[9]; }
    set hash(value) { this.#set("hash", value); }
    get searchParams() { return this.#searchParams; }
    get [Symbol.toStringTag]() { return "URL"; }
    toString() { return this.#href; }
    toJSON() { return this.#href; }
  }

  define("URL", URL);
  define("URLSearchParams", URLSearchParams);
})();
"#;
/// The name rquickjs gives every evaluated script while its `std` feature,
/// which would allow choosing one, is off.
const ENGINE_SCRIPT_NAME: &str = "eval_script";
/// The name failure positions use for the submitted program.
const PROGRAM_SCRIPT_NAME: &str = "program";

#[derive(Debug, PartialEq, Eq)]
struct RunnerExecutionFailure {
    code: RunnerFailureCode,
    message: String,
}

struct ExecutionCapabilities<F, P, A, W, C> {
    call: F,
    pause: P,
    artifact: A,
    wait: W,
    console: C,
    artifacts_available: bool,
}

impl RunnerExecutionFailure {
    fn new(code: RunnerFailureCode, message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            code,
            message: bounded_failure_message(&message),
        }
    }
}

pub fn run() -> anyhow::Result<()> {
    let spool = open_result_spool()?;
    let (runtime, deadline_reached, deadline) = create_runtime_armable()?;
    let context = JsContext::full(&runtime).context("create JavaScript context")?;
    apply_resource_limits()?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    // Rust initializes its process-wide stdio handles with a metadata syscall.
    // Establish them before confinement, then reuse only the inherited pipes.
    drop(stdin.lock());
    drop(stdout.lock());
    apply_confinement()?;
    write_runner_frame(
        &mut stdout.lock(),
        &RunnerFrame::Ready {
            confinement_profile: CONFINEMENT_PROFILE.to_owned(),
        },
    )?;

    let mut input = stdin.lock();
    let start = read_parent_frame(&mut input)?;
    let ParentFrame::Start {
        source,
        bindings,
        resume,
        input: program_input,
        artifacts_available,
        execution_limit_ms,
    } = start
    else {
        return Err(anyhow!("runner expected a start frame"));
    };

    // The parent has already bounded this against operator policy; the runner
    // applies it rather than deciding one.
    deadline.arm(execution_limit_ms);

    drop(input);
    let outcome = execute_in(
        &context,
        &source,
        &bindings,
        resume.as_ref(),
        &program_input,
        ExecutionCapabilities {
            call: runner_call(spool),
            pause: runner_pause(),
            artifact: runner_artifact(),
            wait: runner_wait(deadline.clone(), deadline_reached.clone()),
            console: runner_console(),
            artifacts_available,
        },
        &deadline_reached,
    );
    let mut output = stdout.lock();
    match outcome {
        Ok(result) => write_runner_frame(&mut output, &RunnerFrame::Complete { result }),
        Err(error) => write_runner_frame(
            &mut output,
            &RunnerFrame::Failed {
                code: error.code,
                message: error.message,
            },
        ),
    }
}

fn open_result_spool() -> anyhow::Result<File> {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    let mode = arguments.next();
    let spool_flag = arguments.next();
    let spool_path = arguments.next().map(PathBuf::from);
    let configured_limits = arguments.next();
    if mode.as_deref() != Some(std::ffi::OsStr::new(super::codemode_protocol::RUNNER_FLAG))
        || spool_flag.as_deref() != Some(std::ffi::OsStr::new(RUNNER_SPOOL_FLAG))
        || spool_path.is_none()
        || arguments.next().is_some()
    {
        return Err(anyhow!("runner requires exactly one result spool"));
    }
    if let Some(encoded) = configured_limits {
        crate::codemode_limits::install(serde_json::from_str(
            encoded.to_str().context("limits must be UTF-8")?,
        )?)?;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(spool_path.expect("checked above"))
        .context("open Code Mode result spool")
}

fn runner_pause() -> impl Fn(&str) -> rquickjs::Result<String> {
    move |checkpoint_json| {
        if checkpoint_json.len() > limits().checkpoint_bytes {
            return Err(rquickjs::Error::new_from_js_message(
                "checkpoint",
                "pause request",
                "checkpoint exceeds the protocol limit",
            ));
        }
        let checkpoint: Value = serde_json::from_str(checkpoint_json).map_err(|_| {
            rquickjs::Error::new_from_js_message(
                "checkpoint",
                "pause request",
                "checkpoint must be JSON-compatible",
            )
        })?;
        let stdout = std::io::stdout();
        write_runner_frame(&mut stdout.lock(), &RunnerFrame::Pause { checkpoint }).map_err(
            |_| {
                rquickjs::Error::new_from_js_message(
                    "checkpoint",
                    "pause request",
                    "checkpoint transport failed",
                )
            },
        )?;

        // The parent durably records the checkpoint and closes this attempt.
        // Waiting on the inherited pipe prevents user code from advancing past
        // the boundary before the kill-on-drop parent tears down the runner.
        let stdin = std::io::stdin();
        let _ = read_parent_frame(&mut stdin.lock());
        Err(rquickjs::Error::new_from_js_message(
            "checkpoint",
            "pause request",
            "execution paused",
        ))
    }
}

fn runner_call(spool: File) -> impl Fn(&str) -> rquickjs::Result<String> {
    let next_id = AtomicU32::new(1);
    let spool = std::sync::Mutex::new(spool);
    move |request_json| {
        let request: Value = serde_json::from_str(request_json).map_err(|_| {
            rquickjs::Error::new_from_js_message("string", "request", "invalid connector request")
        })?;
        let call_id = request
            .get("call_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                rquickjs::Error::new_from_js_message(
                    "request",
                    "connector call",
                    "connector call id must be a string",
                )
            })?
            .to_owned();
        let arguments = request
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default()));
        if !arguments.is_object() {
            return Err(rquickjs::Error::new_from_js_message(
                "request",
                "connector call",
                "connector arguments must be an object",
            ));
        }
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let stdout = std::io::stdout();
        write_runner_frame(
            &mut stdout.lock(),
            &RunnerFrame::Call {
                id,
                call_id,
                arguments,
            },
        )
        .map_err(|_| {
            rquickjs::Error::new_from_js_message(
                "request",
                "connector call",
                "connector transport failed",
            )
        })?;
        let stdin = std::io::stdin();
        match read_parent_frame(&mut stdin.lock()).map_err(|_| {
            rquickjs::Error::new_from_js_message(
                "response",
                "connector call",
                "connector transport failed",
            )
        })? {
            ParentFrame::CallResult {
                id: response_id,
                result,
            } if response_id == id => {
                // Both arms reach the SDK as an envelope: the prelude throws
                // a structured Error (message plus a stable `code` split
                // from the broker's "code: message" contract) for the err
                // arm, so program code branches on `error.code` rather than
                // catching an opaque native exception.
                let envelope = match result {
                    Ok(ConnectorCallResult::Inline { value }) => {
                        serde_json::json!({ "ok": value })
                    }
                    Ok(ConnectorCallResult::Spool { bytes }) => {
                        let mut spool = spool.lock().map_err(|_| {
                            rquickjs::Error::new_from_js_message(
                                "response",
                                "connector call",
                                "connector spool lock failed",
                            )
                        })?;
                        let value =
                            crate::codemode_spool::read_value(&mut spool, bytes).map_err(|_| {
                                rquickjs::Error::new_from_js_message(
                                    "response",
                                    "connector call",
                                    "connector spool read failed",
                                )
                            })?;
                        serde_json::json!({ "ok": value })
                    }
                    Err(message) => serde_json::json!({ "err": message }),
                };
                Ok(envelope.to_string())
            }
            _ => Err(rquickjs::Error::new_from_js_message(
                "response",
                "connector call",
                "unexpected connector response",
            )),
        }
    }
}

fn runner_artifact() -> impl Fn(&str) -> rquickjs::Result<String> {
    let next_id = AtomicU32::new(1);
    move |artifact_json| {
        if artifact_json.len() > limits().artifact_bytes {
            let stdout = std::io::stdout();
            let _ = write_runner_frame(
                &mut stdout.lock(),
                &RunnerFrame::Failed {
                    code: RunnerFailureCode::ArtifactTooLarge,
                    message: "Code Mode artifact exceeded its size limit".to_owned(),
                },
            );
            return Err(rquickjs::Error::new_from_js_message(
                "artifact",
                "artifact emission",
                "artifact exceeds the protocol limit",
            ));
        }
        let value: Value = serde_json::from_str(artifact_json).map_err(|_| {
            rquickjs::Error::new_from_js_message(
                "artifact",
                "artifact emission",
                "artifact must be JSON-compatible",
            )
        })?;
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let stdout = std::io::stdout();
        write_runner_frame(&mut stdout.lock(), &RunnerFrame::Artifact { id, value }).map_err(
            |_| {
                rquickjs::Error::new_from_js_message(
                    "artifact",
                    "artifact emission",
                    "artifact transport failed",
                )
            },
        )?;
        let stdin = std::io::stdin();
        match read_parent_frame(&mut stdin.lock()).map_err(|_| {
            rquickjs::Error::new_from_js_message(
                "artifact",
                "artifact emission",
                "artifact transport failed",
            )
        })? {
            ParentFrame::ArtifactResult {
                id: response_id,
                result,
            } if response_id == id => result.map(|value| value.to_string()).map_err(|message| {
                rquickjs::Error::new_from_js_message("artifact", "artifact emission", message)
            }),
            _ => Err(rquickjs::Error::new_from_js_message(
                "artifact",
                "artifact emission",
                "unexpected artifact response",
            )),
        }
    }
}

/// Send each console call to the parent until the console budget is spent.
///
/// The parent applies the same budget again, so this only saves the work of
/// sending output that would be dropped.
fn runner_console() -> impl Fn(ConsoleLevel, &str) -> rquickjs::Result<()> {
    let capture = std::sync::Mutex::new(ConsoleCapture::new(limits().console_bytes));
    move |level, text| {
        let mut capture = capture.lock().map_err(|_| {
            rquickjs::Error::new_from_js_message("console", "console output", "console lock failed")
        })?;
        let stdout = std::io::stdout();
        for frame in console_frames(&mut capture, level, text) {
            write_runner_frame(&mut stdout.lock(), &frame).map_err(|_| {
                rquickjs::Error::new_from_js_message(
                    "console",
                    "console output",
                    "console transport failed",
                )
            })?;
        }
        Ok(())
    }
}

/// The frames that deliver one console call: the entry as the budget keeps
/// it, then a truncation notice the first time the budget cuts or drops
/// output.
fn console_frames(
    capture: &mut ConsoleCapture,
    level: ConsoleLevel,
    text: &str,
) -> Vec<RunnerFrame> {
    if capture.is_truncated() {
        return Vec::new();
    }
    let mut frames = Vec::new();
    if let Some(entry) = capture.admit(level, text) {
        frames.push(RunnerFrame::Console {
            level: entry.level,
            text: entry.text.clone(),
        });
    }
    if capture.is_truncated() {
        frames.push(RunnerFrame::ConsoleTruncated);
    }
    frames
}

#[cfg(test)]
fn execute_with<F>(
    source: &str,
    bindings: &[RunnerBinding],
    call: F,
) -> Result<Value, RunnerExecutionFailure>
where
    F: Fn(&str) -> rquickjs::Result<String> + 'static,
{
    execute_with_resume(source, bindings, ProgramData::default(), call, |_| {
        Err(rquickjs::Error::new_from_js_message(
            "checkpoint",
            "pause request",
            "pause is unavailable in this test",
        ))
    })
}

/// The two channels that hand a program its data: the checkpoint and input a
/// continuation resumes from, and the input its caller submitted. They travel
/// together everywhere a program starts, so they are named together here.
#[cfg(test)]
#[derive(Default, Clone, Copy)]
struct ProgramData<'a> {
    resume: Option<&'a RunnerResumeContext>,
    input: Option<&'a Value>,
}

#[cfg(test)]
fn execute_with_resume<F, P>(
    source: &str,
    bindings: &[RunnerBinding],
    data: ProgramData<'_>,
    call: F,
    pause: P,
) -> Result<Value, RunnerExecutionFailure>
where
    F: Fn(&str) -> rquickjs::Result<String> + 'static,
    P: Fn(&str) -> rquickjs::Result<String> + 'static,
{
    execute_with_capabilities(
        source,
        bindings,
        data,
        call,
        pause,
        |_| {
            Err(rquickjs::Error::new_from_js_message(
                "artifact",
                "artifact emission",
                "artifacts are unavailable in this test",
            ))
        },
        |_, _| Ok(()),
        false,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn execute_with_capabilities<F, P, A, C>(
    source: &str,
    bindings: &[RunnerBinding],
    data: ProgramData<'_>,
    call: F,
    pause: P,
    artifact: A,
    console: C,
    artifacts_available: bool,
) -> Result<Value, RunnerExecutionFailure>
where
    F: Fn(&str) -> rquickjs::Result<String> + 'static,
    P: Fn(&str) -> rquickjs::Result<String> + 'static,
    A: Fn(&str) -> rquickjs::Result<String> + 'static,
    C: Fn(ConsoleLevel, &str) -> rquickjs::Result<()> + 'static,
{
    let (runtime, deadline_reached, deadline) = create_runtime_armable().map_err(|_| {
        RunnerExecutionFailure::new(
            RunnerFailureCode::RunnerInternal,
            "Code Mode runner could not initialize",
        )
    })?;
    deadline.arm(u64::try_from(EXECUTION_LIMIT.as_millis()).unwrap_or(u64::MAX));
    let context = JsContext::full(&runtime).map_err(|_| {
        RunnerExecutionFailure::new(
            RunnerFailureCode::RunnerInternal,
            "Code Mode runner could not initialize",
        )
    })?;
    execute_in(
        &context,
        source,
        bindings,
        data.resume,
        data.input.unwrap_or(&Value::Null),
        ExecutionCapabilities {
            call,
            pause,
            artifact,
            wait: runner_wait(deadline, deadline_reached.clone()),
            console,
            artifacts_available,
        },
        &deadline_reached,
    )
}

/// Create a runtime whose deadline can be re-armed once the parent's start
/// frame arrives.
///
/// The runtime must exist before confinement is applied and before the frame
/// is read, so the budget cannot be known at creation time. It therefore
/// starts at the default and is narrowed or widened once, to the value the
/// parent computed under operator policy. Starting at the default rather than
/// unbounded means a runner that never receives a frame is still bounded.
fn create_runtime_armable() -> anyhow::Result<(Runtime, Arc<AtomicBool>, ArmableDeadline)> {
    let runtime = Runtime::new().context("create JavaScript runtime")?;
    runtime.set_memory_limit(limits().heap_bytes);
    runtime.set_max_stack_size(limits().stack_bytes);
    // Both the origin and the budget move when the parent's frame arrives, so
    // startup, confinement and frame I/O are not charged against a program's
    // grant. Until then the default applies from now, which keeps a runner
    // that never receives a frame bounded.
    let origin_ms = Arc::new(AtomicU64::new(0));
    let process_start = Instant::now();
    let budget_ms = Arc::new(AtomicU64::new(
        u64::try_from(EXECUTION_LIMIT.as_millis()).unwrap_or(u64::MAX),
    ));
    let deadline_reached = Arc::new(AtomicBool::new(false));
    let interrupt_deadline_reached = deadline_reached.clone();
    let interrupt_budget = budget_ms.clone();
    let interrupt_origin = origin_ms.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        let now_ms = u64::try_from(process_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let elapsed = now_ms.saturating_sub(interrupt_origin.load(Ordering::Relaxed));
        let reached = elapsed >= interrupt_budget.load(Ordering::Relaxed);
        if reached {
            interrupt_deadline_reached.store(true, Ordering::Relaxed);
        }
        reached
    })));
    Ok((
        runtime,
        deadline_reached,
        ArmableDeadline {
            budget_ms,
            origin_ms,
            process_start,
        },
    ))
}

/// Handle for narrowing or widening a live runtime's deadline exactly once,
/// when the parent's budget for this execution becomes known.
#[derive(Clone)]
struct ArmableDeadline {
    budget_ms: Arc<AtomicU64>,
    origin_ms: Arc<AtomicU64>,
    process_start: Instant,
}

impl ArmableDeadline {
    /// Start the granted budget now.
    ///
    /// Setting the origin as well as the duration is the point: a program's
    /// grant should measure its own execution, not the startup and frame I/O
    /// that preceded it.
    fn arm(&self, budget_ms: u64) {
        let now_ms = u64::try_from(self.process_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.origin_ms.store(now_ms, Ordering::Relaxed);
        self.budget_ms.store(budget_ms, Ordering::Relaxed);
    }

    /// Milliseconds left of the granted budget, from the same origin and by
    /// the same arithmetic the interrupt handler uses. Zero once spent.
    fn remaining_ms(&self) -> u64 {
        let now_ms = u64::try_from(self.process_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let elapsed = now_ms.saturating_sub(self.origin_ms.load(Ordering::Relaxed));
        self.budget_ms
            .load(Ordering::Relaxed)
            .saturating_sub(elapsed)
    }
}

/// Pace a program without spinning.
///
/// A poll loop has to let time pass, and the only way to do that in a runtime
/// with no timers is to burn a core. This sleeps instead, which the syscall
/// profile already permits: `nanosleep` and `clock_nanosleep` are on the
/// allow-list, so this adds a timer and not a route to anything else.
///
/// **Waiting spends the budget rather than pausing it.** The deadline's origin
/// does not move, so elapsed sleep counts exactly as elapsed computation does,
/// and a wait is clamped to what remains. That is what stops sleep being used
/// to outlive the operator's ceiling; the bound on a single wait is therefore
/// the remaining budget rather than a second limit to reason about.
///
/// **Running out of budget is not this primitive's failure to report.** A wait
/// that spends what remains marks the shared deadline and aborts evaluation,
/// so the runner reports the timeout reason it has always used. A final
/// deadline check after evaluation also prevents a program from catching the
/// native error and turning an exhausted budget into a successful result.
/// Refusing the duration as an ordinary program error would give the opposite
/// remedy: read the code rather than raise the limit.
fn runner_wait(
    deadline: ArmableDeadline,
    deadline_reached: Arc<AtomicBool>,
) -> impl Fn(f64) -> rquickjs::Result<String> {
    move |requested| {
        let refusal = |code: &str, message: &str| {
            Ok(serde_json::json!({"err": {"code": code, "message": message}}).to_string())
        };
        if !requested.is_finite() || requested < 0.0 {
            return refusal(
                "execution_wait_invalid",
                "wait expects a non-negative number of milliseconds",
            );
        }
        // Truncation is deliberate: sub-millisecond precision is not something
        // this can honour, and rounding up could exceed a checked remainder.
        let requested_ms = requested.trunc() as u64;
        let remaining_ms = deadline.remaining_ms();
        std::thread::sleep(Duration::from_millis(requested_ms.min(remaining_ms)));
        if requested_ms >= remaining_ms || deadline.remaining_ms() == 0 {
            deadline_reached.store(true, Ordering::Relaxed);
            return Err(rquickjs::Error::new_from_js_message(
                "wait",
                "execution deadline",
                "execution budget exhausted while waiting",
            ));
        }
        Ok(serde_json::json!({"ok": Value::Null}).to_string())
    }
}

/// Whether a program may still use host capabilities.
///
/// Every capability is refused once the shared execution deadline has fired.
/// QuickJS exceptions are deliberately catchable program errors. The runner's
/// final deadline check still selects the stable timeout result, while this
/// guard prevents code in a catch block from reaching a connector, publishing
/// an artifact, or checkpointing after the operator's budget is exhausted.
///
/// Every capability is also refused once the program's promise has settled.
/// Reporting a failure reads the thrown value's properties, and a getter or
/// proxy there runs program code; closing the capabilities first keeps that
/// code from causing any effect after the program has finished.
#[derive(Clone)]
struct HostGate {
    deadline_reached: Arc<AtomicBool>,
    settled: Arc<AtomicBool>,
}

impl HostGate {
    fn require_open(&self) -> rquickjs::Result<()> {
        if self.deadline_reached.load(Ordering::Relaxed) {
            return Err(rquickjs::Error::new_from_js_message(
                "execution",
                "host capability",
                "execution budget is exhausted",
            ));
        }
        if self.settled.load(Ordering::Relaxed) {
            return Err(rquickjs::Error::new_from_js_message(
                "execution",
                "host capability",
                "the program has finished",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
fn create_runtime_with_limit(
    execution_limit: Duration,
) -> anyhow::Result<(Runtime, Arc<AtomicBool>)> {
    let runtime = Runtime::new().context("create JavaScript runtime")?;
    runtime.set_memory_limit(limits().heap_bytes);
    runtime.set_max_stack_size(limits().stack_bytes);
    let deadline = Instant::now() + execution_limit;
    let deadline_reached = Arc::new(AtomicBool::new(false));
    let interrupt_deadline_reached = deadline_reached.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        let reached = Instant::now() >= deadline;
        if reached {
            interrupt_deadline_reached.store(true, Ordering::Relaxed);
        }
        reached
    })));
    Ok((runtime, deadline_reached))
}

#[cfg(target_os = "linux")]
fn apply_resource_limits() -> anyhow::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: limits().address_space_bytes as u64,
        rlim_max: limits().address_space_bytes as u64,
    };
    // The runner must establish its kernel-enforced address-space ceiling
    // before accepting source or installing callable host capabilities.
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) } != 0 {
        return Err(std::io::Error::last_os_error()).context("limit runner address space");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_resource_limits() -> anyhow::Result<()> {
    Err(anyhow!(
        "Code Mode execution requires Linux process resource limits"
    ))
}

fn execute_in<F, P, A, W, C>(
    context: &JsContext,
    source: &str,
    bindings: &[RunnerBinding],
    resume: Option<&RunnerResumeContext>,
    input: &Value,
    capabilities: ExecutionCapabilities<F, P, A, W, C>,
    deadline_reached: &Arc<AtomicBool>,
) -> Result<Value, RunnerExecutionFailure>
where
    F: Fn(&str) -> rquickjs::Result<String> + 'static,
    P: Fn(&str) -> rquickjs::Result<String> + 'static,
    A: Fn(&str) -> rquickjs::Result<String> + 'static,
    W: Fn(f64) -> rquickjs::Result<String> + 'static,
    C: Fn(ConsoleLevel, &str) -> rquickjs::Result<()> + 'static,
{
    let bindings_json = serde_json::to_string(bindings).map_err(|_| {
        RunnerExecutionFailure::new(
            RunnerFailureCode::RunnerInternal,
            "Code Mode runner could not install connector bindings",
        )
    })?;
    let resume_json = serde_json::to_string(&resume).map_err(|_| {
        RunnerExecutionFailure::new(
            RunnerFailureCode::RunnerInternal,
            "Code Mode runner could not install resume context",
        )
    })?;
    // Serialized, handed to the sandbox as a string, and parsed there with the
    // captured `JSON.parse`. Caller-supplied input reaches the program as data
    // and is never evaluated as code.
    let input_json = serde_json::to_string(input).map_err(|_| {
        RunnerExecutionFailure::new(
            RunnerFailureCode::RunnerInternal,
            "Code Mode runner could not install program input",
        )
    })?;
    let ExecutionCapabilities {
        call,
        pause,
        artifact,
        wait,
        console,
        artifacts_available,
    } = capabilities;
    context.with(|ctx| {
        // Set only after the parent has produced a valid encoded connector
        // envelope, before rquickjs converts the Rust String into a JS value.
        // It therefore covers both that allocation and JSON decoding, while a
        // native transport error never enters the materialization state.
        let connector_materialization_in_progress = Arc::new(AtomicBool::new(false));
        let gate = HostGate {
            deadline_reached: deadline_reached.clone(),
            settled: Arc::new(AtomicBool::new(false)),
        };
        let call_gate = gate.clone();
        let call_materialization = Arc::clone(&connector_materialization_in_progress);
        ctx.globals()
            .set(
                "__gateway_call",
                Func::from(move |request: JsString<'_>| -> rquickjs::Result<String> {
                    call_materialization.store(false, Ordering::Relaxed);
                    call_gate.require_open()?;
                    let request = request.to_cstring()?;
                    validate_connector_request(request.as_str(), limits().request_bytes)?;
                    let encoded = call(request.as_str())?;
                    call_materialization.store(true, Ordering::Relaxed);
                    Ok(encoded)
                }),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install connector bindings",
                )
            })?;
        let queried_materialization = Arc::clone(&connector_materialization_in_progress);
        ctx.globals()
            .set(
                "__gateway_connector_materializing",
                Func::from(move || queried_materialization.load(Ordering::Relaxed)),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install connector bindings",
                )
            })?;
        let completed_materialization = Arc::clone(&connector_materialization_in_progress);
        ctx.globals()
            .set(
                "__gateway_connector_materialized",
                Func::from(move || {
                    completed_materialization.store(false, Ordering::Relaxed);
                }),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install connector bindings",
                )
            })?;
        let pause_gate = gate.clone();
        ctx.globals()
            .set(
                "__gateway_pause",
                Func::from(move |checkpoint: JsString<'_>| {
                    pause_gate.require_open()?;
                    let checkpoint = checkpoint.to_cstring()?;
                    pause(checkpoint.as_str())
                }),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install the pause boundary",
                )
            })?;
        let artifact_gate = gate.clone();
        ctx.globals()
            .set(
                "__gateway_artifact",
                Func::from(move |value: JsString<'_>| {
                    artifact_gate.require_open()?;
                    let value = value.to_cstring()?;
                    artifact(value.as_str())
                }),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install artifact emission",
                )
            })?;
        let wait_gate = gate.clone();
        ctx.globals()
            .set(
                "__gateway_wait",
                Func::from(move |milliseconds: f64| {
                    wait_gate.require_open()?;
                    wait(milliseconds)
                }),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install the wait primitive",
                )
            })?;
        ctx.globals()
            .set("__gateway_bindings_json", bindings_json)
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install connector bindings",
                )
            })?;
        ctx.globals()
            .set("__gateway_resume_json", resume_json)
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install resume context",
                )
            })?;
        ctx.globals()
            .set("__gateway_artifacts_available", artifacts_available)
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install artifact availability",
                )
            })?;
        ctx.globals()
            .set("__gateway_input_json", input_json)
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install program input",
                )
            })?;

        let prelude = format!(
            r#"
"use strict";
const gatewayJsonParse = JSON.parse;
const gatewayJsonStringify = JSON.stringify;
const gatewayObjectCreate = Object.create;
const gatewayDefineProperty = Object.defineProperty;
const GatewayError = Error;
const gatewayStringIndexOf = Function.prototype.call.bind(String.prototype.indexOf);
const gatewayStringSlice = Function.prototype.call.bind(String.prototype.slice);
const gatewayRegexTest = Function.prototype.call.bind(RegExp.prototype.test);
const gatewayHasOwn = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
const gatewayCodePattern = /^[a-z][a-z0-9_]*$/;
const connectors = (() => {{
  const gatewayCall = __gateway_call;
  const gatewayConnectorMaterializing = __gateway_connector_materializing;
  const gatewayConnectorMaterialized = __gateway_connector_materialized;
  const bindingSpecs = gatewayJsonParse(__gateway_bindings_json);
  delete globalThis.__gateway_call;
  delete globalThis.__gateway_connector_materializing;
  delete globalThis.__gateway_connector_materialized;
  delete globalThis.__gateway_bindings_json;
  const gatewayMaterializationError = () => {{
    const error = new GatewayError("{CONNECTOR_MATERIALIZATION_FAILURE}");
    gatewayDefineProperty(error, "code", {{
      value: "connector_result_too_large",
      enumerable: true
    }});
    gatewayConnectorMaterialized();
    return error;
  }};
  const generated = gatewayObjectCreate(null);
  for (const binding of bindingSpecs) {{
    let connector = generated[binding.connector];
    if (connector === undefined) {{
      connector = gatewayObjectCreate(null);
      gatewayDefineProperty(generated, binding.connector, {{
        value: connector,
        enumerable: true
      }});
    }}
    gatewayDefineProperty(connector, binding.operation, {{
      value: (args = {{}}) => {{
        const request = gatewayObjectCreate(null);
        gatewayDefineProperty(request, "call_id", {{
          value: binding.call_id,
          enumerable: true
        }});
        gatewayDefineProperty(request, "arguments", {{
          value: args,
          enumerable: true
        }});
        let encodedEnvelope;
        try {{
          encodedEnvelope = gatewayCall(gatewayJsonStringify(request));
        }} catch (cause) {{
          if (!gatewayConnectorMaterializing()) {{
            throw cause;
          }}
          throw gatewayMaterializationError();
        }}
        let envelope;
        try {{
          envelope = gatewayJsonParse(encodedEnvelope);
        }} catch {{
          throw gatewayMaterializationError();
        }}
        gatewayConnectorMaterialized();
        if (gatewayHasOwn(envelope, "err")) {{
          const separator = gatewayStringIndexOf(envelope.err, ": ");
          const candidate = separator > 0
            ? gatewayStringSlice(envelope.err, 0, separator)
            : "";
          const recognized = candidate !== ""
            && gatewayRegexTest(gatewayCodePattern, candidate);
          const error = new GatewayError(recognized
            ? gatewayStringSlice(envelope.err, separator + 2)
            : envelope.err);
          gatewayDefineProperty(error, "code", {{
            value: recognized ? candidate : "connector_failure",
            enumerable: true
          }});
          throw error;
        }}
        return envelope.ok;
      }},
      enumerable: true
    }});
  }}
  for (const connectorName of Object.keys(generated)) {{
    Object.freeze(generated[connectorName]);
  }}
  return Object.freeze(generated);
}})();
const execution = (() => {{
  const gatewayPause = __gateway_pause;
  const gatewayArtifact = __gateway_artifact;
  const gatewayWait = __gateway_wait;
  const resume = gatewayJsonParse(__gateway_resume_json);
  const input = gatewayJsonParse(__gateway_input_json);
  const artifactsAvailable = __gateway_artifacts_available;
  delete globalThis.__gateway_pause;
  delete globalThis.__gateway_artifact;
  delete globalThis.__gateway_wait;
  delete globalThis.__gateway_resume_json;
  delete globalThis.__gateway_input_json;
  delete globalThis.__gateway_artifacts_available;
  const generated = gatewayObjectCreate(null);
  gatewayDefineProperty(generated, "resume", {{
    value: resume,
    enumerable: true
  }});
  gatewayDefineProperty(generated, "input", {{
    value: input,
    enumerable: true
  }});
  gatewayDefineProperty(generated, "pause", {{
    value: (checkpoint = {{}}) =>
      gatewayPause(gatewayJsonStringify(checkpoint)),
    enumerable: true
  }});
  gatewayDefineProperty(generated, "artifactsAvailable", {{
    value: artifactsAvailable,
    enumerable: true
  }});
  gatewayDefineProperty(generated, "emitArtifact", {{
    value: (value) =>
      gatewayJsonParse(gatewayArtifact(gatewayJsonStringify(value))),
    enumerable: true
  }});
  gatewayDefineProperty(generated, "wait", {{
    value: (milliseconds) => {{
      const envelope = gatewayJsonParse(gatewayWait(milliseconds));
      if (gatewayHasOwn(envelope, "err")) {{
        const error = new GatewayError(envelope.err.message);
        gatewayDefineProperty(error, "code", {{
          value: envelope.err.code,
          enumerable: true
        }});
        throw error;
      }}
      return envelope.ok;
    }},
    enumerable: true
  }});
  return Object.freeze(generated);
}})();
{CONSOLE_PRELUDE}{STANDARD_HELPERS_PRELUDE}{URL_PRELUDE}(async () => {{
  const gatewayProgramResult = await (async () => {{
"#
        );
        let layout = ProgramLayout::new(&prelude, source);
        let console_gate = gate.clone();
        ctx.globals()
            .set(
                "__gateway_console",
                Func::from(
                    move |level: JsString<'_>, text: JsString<'_>| -> rquickjs::Result<()> {
                        console_gate.require_open()?;
                        let level = match level.to_string()?.as_str() {
                            "debug" => ConsoleLevel::Debug,
                            "info" => ConsoleLevel::Info,
                            "warn" => ConsoleLevel::Warn,
                            "error" => ConsoleLevel::Error,
                            _ => ConsoleLevel::Log,
                        };
                        console(level, &text.to_string()?)
                    },
                ),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install the console",
                )
            })?;
        // Error stacks the console prints name the same positions a failure
        // would, so the prelude restates them the same way.
        ctx.globals()
            .set(
                "__gateway_program_stack",
                Func::from(move |stack: String| layout.program_stack(&stack)),
            )
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install the console",
                )
            })?;
        ctx.globals()
            .set("__gateway_console_bytes", limits().console_bytes)
            .map_err(|_| {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::RunnerInternal,
                    "Code Mode runner could not install the console",
                )
            })?;
        install_standard_helpers(&ctx).map_err(|_| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::RunnerInternal,
                "Code Mode runner could not install the standard helpers",
            )
        })?;
        let wrapped = format!("{prelude}{source}{PROGRAM_EPILOGUE}");
        let evaluated = match ctx.eval::<Promise<'_>, _>(wrapped).catch(&ctx) {
            Ok(program) => settle_program(&ctx, &program, deadline_reached),
            Err(error) => ProgramSettlement::Settled(Err(error)),
        };
        gate.settled.store(true, Ordering::Relaxed);
        if deadline_reached.load(Ordering::Relaxed) {
            return Err(RunnerExecutionFailure::new(
                RunnerFailureCode::ExecutionTimeout,
                "Code Mode execution exceeded its time limit",
            ));
        }
        let ProgramSettlement::Settled(evaluated) = evaluated else {
            return Err(RunnerExecutionFailure::new(
                RunnerFailureCode::ProgramFailed,
                "Code Mode program never finished: it is waiting on a promise that nothing \
                 left to run can settle",
            ));
        };
        let result_json = evaluated.map_err(|error| {
            let is_stable_connector_error = match &error {
                CaughtError::Exception(exception) => {
                    exception
                        .as_object()
                        .get::<_, Option<String>>("code")
                        .ok()
                        .flatten()
                        .as_deref()
                        == Some("connector_result_too_large")
                }
                CaughtError::Value(value) => value.as_object().is_some_and(|object| {
                    object
                        .get::<_, Option<String>>("code")
                        .ok()
                        .flatten()
                        .as_deref()
                        == Some("connector_result_too_large")
                }),
                CaughtError::Error(_) => false,
            };
            if connector_materialization_in_progress.load(Ordering::Relaxed)
                || is_stable_connector_error
            {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::ConnectorResultTooLarge,
                    "Code Mode connector result exceeded runtime materialization capacity",
                )
            } else {
                RunnerExecutionFailure::new(
                    RunnerFailureCode::ProgramFailed,
                    format!(
                        "Code Mode program evaluation failed: {}",
                        describe_program_error(&error, layout)
                    ),
                )
            }
        })?;
        let result_json = result_json.ok_or_else(|| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::ResultNotJson,
                "Code Mode program must return a JSON-compatible value",
            )
        })?;
        let result_json = result_json.to_cstring().map_err(|_| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::ResultNotJson,
                "Code Mode program must return a JSON-compatible value",
            )
        })?;
        if result_json.len() > limits().result_bytes + RESULT_ENVELOPE_OVERHEAD_BYTES {
            return Err(RunnerExecutionFailure::new(
                RunnerFailureCode::ResultTooLarge,
                "Code Mode execution result exceeded its size limit",
            ));
        }
        let envelope: Value = serde_json::from_str(result_json.as_str()).map_err(|_| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::ResultNotJson,
                "Code Mode program must return a JSON-compatible value",
            )
        })?;
        let result = envelope.get("result").cloned().ok_or_else(|| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::ResultNotJson,
                "Code Mode program must return a JSON-compatible value",
            )
        })?;
        let encoded_result = serde_json::to_vec(&result).map_err(|_| {
            RunnerExecutionFailure::new(
                RunnerFailureCode::ResultNotJson,
                "Code Mode program must return a JSON-compatible value",
            )
        })?;
        if encoded_result.len() > limits().result_bytes {
            return Err(RunnerExecutionFailure::new(
                RunnerFailureCode::ResultTooLarge,
                "Code Mode execution result exceeded its size limit",
            ));
        }
        Ok(result)
    })
}

enum ProgramSettlement<'js> {
    Settled(CaughtResult<'js, Option<JsString<'js>>>),
    /// The job queue emptied, or the deadline fired, while the program's
    /// promise was still pending.
    Unsettled,
}

/// Run queued promise jobs until the program's promise settles.
///
/// Connector calls, waits and pauses are synchronous host calls, so the only
/// jobs are the program's own promise reactions. A queue that empties while
/// the promise is pending can never settle it. The interrupt handler still
/// bounds every job, and the deadline is checked between jobs because a job
/// the interrupt aborted reports as executed.
fn settle_program<'js>(
    ctx: &Ctx<'js>,
    program: &Promise<'js>,
    deadline_reached: &AtomicBool,
) -> ProgramSettlement<'js> {
    loop {
        if let Some(outcome) = program.result::<Option<JsString<'js>>>() {
            return ProgramSettlement::Settled(outcome.catch(ctx));
        }
        if deadline_reached.load(Ordering::Relaxed) || !ctx.execute_pending_job() {
            return ProgramSettlement::Unsettled;
        }
    }
}

/// Where the submitted source sits inside the generated script.
///
/// The prelude ends with a line break, so the program's lines keep their
/// columns and only their line numbers are offset.
#[derive(Debug, Clone, Copy)]
struct ProgramLayout {
    first_line: usize,
    last_line: usize,
}

enum ScriptLocation {
    Program {
        line: usize,
        column: Option<usize>,
    },
    /// Past the program's last line: only a parser that ran out of program
    /// reports a position in the closing code that follows it.
    AfterProgram,
    Generated,
    Other,
}

impl ProgramLayout {
    fn new(prelude: &str, source: &str) -> Self {
        let first_line = prelude.matches('\n').count() + 1;
        Self {
            first_line,
            last_line: first_line + engine_line_breaks(source),
        }
    }

    fn locate(&self, location: &str) -> ScriptLocation {
        let Some(position) = location
            .strip_prefix(ENGINE_SCRIPT_NAME)
            .and_then(|position| position.strip_prefix(':'))
        else {
            return ScriptLocation::Other;
        };
        let (line, column) = match position.split_once(':') {
            Some((line, column)) => (line, Some(column)),
            None => (position, None),
        };
        let Ok(line) = line.parse::<usize>() else {
            return ScriptLocation::Other;
        };
        let column = match column.map(str::parse::<usize>) {
            Some(Ok(column)) => Some(column),
            Some(Err(_)) => return ScriptLocation::Other,
            None => None,
        };
        if line < self.first_line {
            ScriptLocation::Generated
        } else if line > self.last_line {
            ScriptLocation::AfterProgram
        } else {
            ScriptLocation::Program {
                line: line - self.first_line + 1,
                column,
            }
        }
    }

    /// Restate an engine stack trace in the submitted program's positions.
    ///
    /// Frames in the gateway's generated code are dropped because they are
    /// not the program's to act on; native frames are kept because they name
    /// the built-in that threw.
    fn program_stack(&self, stack: &str) -> String {
        stack
            .lines()
            .filter_map(|line| self.program_frame(line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn program_frame(&self, line: &str) -> Option<String> {
        let frame = line.trim_start();
        let indent = &line[..line.len() - frame.len()];
        let Some(frame) = frame.strip_prefix("at ") else {
            return Some(line.to_owned());
        };
        if let Some((function, location)) = frame
            .strip_suffix(')')
            .and_then(|frame| frame.rsplit_once(" ("))
        {
            return match self.locate(location) {
                ScriptLocation::Program { line, column } => Some(format!(
                    "{indent}at {function} ({})",
                    program_position(line, column)
                )),
                ScriptLocation::AfterProgram | ScriptLocation::Generated => None,
                ScriptLocation::Other => Some(line.to_owned()),
            };
        }
        // A frame without a function name is the parser's position. The
        // engine reports its scanner column rather than the offending token's,
        // so only the line is given.
        match self.locate(frame) {
            ScriptLocation::Program { line, .. } => {
                Some(format!("{indent}at {}", program_position(line, None)))
            }
            ScriptLocation::AfterProgram => Some(format!("{indent}at the end of the program")),
            ScriptLocation::Generated => None,
            ScriptLocation::Other => Some(line.to_owned()),
        }
    }
}

/// The JavaScript `typeof` name of a value, which agents recognize, rather than
/// the engine's tag name.
fn javascript_type(value: &rquickjs::Value<'_>) -> &'static str {
    match value.type_of() {
        rquickjs::Type::Uninitialized | rquickjs::Type::Undefined => "undefined",
        rquickjs::Type::Null => "null",
        rquickjs::Type::Bool => "boolean",
        rquickjs::Type::Int | rquickjs::Type::Float => "number",
        rquickjs::Type::String => "string",
        rquickjs::Type::Symbol => "symbol",
        rquickjs::Type::BigInt => "bigint",
        rquickjs::Type::Function | rquickjs::Type::Constructor => "function",
        _ => "object",
    }
}

/// Line breaks as the engine counts them between tokens: `\r\n`, a lone `\r`,
/// `\n`, U+2028 and U+2029 each end a line. Inside block comments and string
/// literals the engine counts fewer, so a program's last line computed from
/// this is an upper bound; the positions the engine reports are its own.
fn engine_line_breaks(source: &str) -> usize {
    let mut breaks = 0;
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' => {
                characters.next_if_eq(&'\n');
                breaks += 1;
            }
            '\n' | '\u{2028}' | '\u{2029}' => breaks += 1,
            _ => {}
        }
    }
    breaks
}

fn program_position(line: usize, column: Option<usize>) -> String {
    match column {
        Some(column) => format!("{PROGRAM_SCRIPT_NAME}:{line}:{column}"),
        None => format!("{PROGRAM_SCRIPT_NAME}:{line}"),
    }
}

/// Describe a program failure by its error name, message and the stack frames
/// that lie in the submitted program.
///
/// A thrown value that is not an `Error` is described without serializing it:
/// a primitive by its text, and an object only by its type, because turning an
/// object into text could call the program's own `toJSON` or `toString` after
/// evaluation has ended.
fn describe_program_error(error: &CaughtError<'_>, layout: ProgramLayout) -> String {
    let exception = match error {
        CaughtError::Exception(exception) => exception,
        CaughtError::Value(value) => {
            let kind = javascript_type(value);
            return match kind {
                "object" | "function" => {
                    format!("uncaught {kind}; throw an Error to report a message and position")
                }
                "null" | "undefined" => format!("uncaught {kind}"),
                _ => match value.get::<rquickjs::Coerced<String>>() {
                    Ok(text) => format!("uncaught {kind}: {}", text.0),
                    Err(_) => format!("uncaught {kind}"),
                },
            };
        }
        CaughtError::Error(error) => return error.to_string(),
    };
    let name = exception
        .as_object()
        .get::<_, Option<String>>("name")
        .ok()
        .flatten()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Error".to_owned());
    let mut description = match exception.message() {
        Some(message) if !message.is_empty() => format!("{name}: {message}"),
        _ => name,
    };
    if let Some(stack) = exception.stack() {
        let frames = layout.program_stack(&stack);
        if !frames.is_empty() {
            description.push('\n');
            description.push_str(&frames);
        }
    }
    description
}

/// The most bytes one `crypto.getRandomValues` call may request, as the Web
/// Crypto API specifies.
const RANDOM_BYTES_LIMIT: usize = 65_536;

fn install_standard_helpers(ctx: &Ctx<'_>) -> rquickjs::Result<()> {
    ctx.globals()
        .set("__gateway_utf8_decode", Func::from(utf8_decode))?;
    ctx.globals()
        .set("__gateway_utf8_encode", Func::from(utf8_encode))?;
    ctx.globals()
        .set("__gateway_random_bytes", Func::from(random_bytes))?;
    ctx.globals()
        .set("__gateway_engine_class", Func::from(engine_class))?;
    ctx.globals()
        .set("__gateway_url_parse", Func::from(url_parse))?;
    ctx.globals()
        .set("__gateway_url_components", Func::from(url_components))?;
    ctx.globals()
        .set("__gateway_url_set", Func::from(url_set))?;
    ctx.globals()
        .set("__gateway_form_parse", Func::from(form_parse))?;
    ctx.globals()
        .set("__gateway_form_serialize", Func::from(form_serialize))
}

/// The engine class of a value, for choosing how `structuredClone` copies it:
/// `-1` for a proxy, `0` for a value that is not an object, and otherwise the
/// engine's class number, which the prelude compares with the classes of
/// sample objects rather than interpreting.
fn engine_class(value: rquickjs::Value<'_>) -> i64 {
    if value.is_proxy() {
        return -1;
    }
    if !value.is_object() {
        return 0;
    }
    // SAFETY: `JS_GetClassID` only reads the class recorded in a live value's
    // header; the value is borrowed for the duration of the call.
    i64::from(unsafe { rquickjs::qjs::JS_GetClassID(value.as_raw()) })
}

/// Parse `input` against an optional `base` as the URL Standard does and
/// return the serialized URL, or `None` when either fails to parse.
fn url_parse(input: String, base: Option<String>) -> Option<String> {
    let base = match base {
        Some(base) => Some(url::Url::parse(&base).ok()?),
        None => None,
    };
    url::Url::options()
        .base_url(base.as_ref())
        .parse(&input)
        .ok()
        .map(String::from)
}

fn serialized_url<'js>(ctx: &Ctx<'js>, href: &str) -> rquickjs::Result<url::Url> {
    url::Url::parse(href).map_err(|_| Exception::throw_type(ctx, "not a serialized URL"))
}

/// The URL Standard's getters for one serialized URL, in the order the
/// prelude reads them.
fn url_components<'js>(ctx: Ctx<'js>, href: String) -> rquickjs::Result<Vec<String>> {
    use url::quirks;
    let url = serialized_url(&ctx, &href)?;
    Ok(vec![
        quirks::origin(&url),
        quirks::protocol(&url).to_owned(),
        quirks::username(&url).to_owned(),
        quirks::password(&url).to_owned(),
        quirks::host(&url).to_owned(),
        quirks::hostname(&url).to_owned(),
        quirks::port(&url).to_owned(),
        quirks::pathname(&url).to_owned(),
        quirks::search(&url).to_owned(),
        quirks::hash(&url).to_owned(),
    ])
}

/// Apply one URL Standard setter and return the resulting serialized URL. A
/// value the standard ignores for this URL leaves it unchanged, as a setter
/// does in the standard.
fn url_set<'js>(
    ctx: Ctx<'js>,
    href: String,
    component: String,
    value: String,
) -> rquickjs::Result<String> {
    use url::quirks;
    let mut url = serialized_url(&ctx, &href)?;
    // The setters' errors mean "ignored", which the standard expresses by
    // leaving the URL as it was.
    match component.as_str() {
        "protocol" => {
            let _ = quirks::set_protocol(&mut url, &value);
        }
        "username" => {
            let _ = quirks::set_username(&mut url, &value);
        }
        "password" => {
            let _ = quirks::set_password(&mut url, &value);
        }
        "host" => {
            let _ = quirks::set_host(&mut url, &value);
        }
        "hostname" => {
            let _ = quirks::set_hostname(&mut url, &value);
        }
        "port" => {
            let _ = quirks::set_port(&mut url, &value);
        }
        "pathname" => quirks::set_pathname(&mut url, &value),
        "search" => quirks::set_search(&mut url, &value),
        "hash" => quirks::set_hash(&mut url, &value),
        _ => return Err(Exception::throw_type(&ctx, "unknown URL component")),
    }
    Ok(url.into())
}

/// `application/x-www-form-urlencoded` parsing, which never fails: malformed
/// escapes stay as written and invalid UTF-8 becomes U+FFFD.
fn form_parse(query: String) -> Vec<Vec<String>> {
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(name, value)| vec![name.into_owned(), value.into_owned()])
        .collect()
}

fn form_serialize(names: Vec<String>, values: Vec<String>) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(names.iter().zip(values.iter()))
        .finish()
}

/// Decode `pending` followed by `input` as UTF-8 and return the text with the
/// number of trailing bytes held back for the next streaming call.
///
/// Invalid sequences become U+FFFD by substituting each maximal invalid
/// subpart, as the Encoding Standard requires, unless `fatal` asks for a
/// `TypeError`. With `stream`, an incomplete sequence at the end is held back
/// instead of being replaced.
fn utf8_decode<'js>(
    pending: TypedArray<'js, u8>,
    input: TypedArray<'js, u8>,
    fatal: bool,
    stream: bool,
) -> rquickjs::Result<List<(String, usize)>> {
    let ctx = input.ctx().clone();
    let (Some(pending), Some(input)) = (pending.as_bytes(), input.as_bytes()) else {
        return Err(Exception::throw_type(
            &ctx,
            "TextDecoder cannot decode a detached buffer",
        ));
    };
    let joined;
    let mut rest: &[u8] = if pending.is_empty() {
        input
    } else {
        joined = [pending, input].concat();
        &joined
    };
    let mut text = String::with_capacity(rest.len());
    loop {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                text.push_str(valid);
                return Ok(List((text, 0)));
            }
            Err(error) => {
                let (valid, after) = rest.split_at(error.valid_up_to());
                text.push_str(std::str::from_utf8(valid).expect("prefix is valid UTF-8"));
                match error.error_len() {
                    None if stream => return Ok(List((text, after.len()))),
                    _ if fatal => {
                        return Err(Exception::throw_type(
                            &ctx,
                            "The encoded data was not valid UTF-8",
                        ))
                    }
                    None => {
                        text.push(char::REPLACEMENT_CHARACTER);
                        return Ok(List((text, 0)));
                    }
                    Some(length) => {
                        text.push(char::REPLACEMENT_CHARACTER);
                        rest = &after[length..];
                    }
                }
            }
        }
    }
}

/// Encode text the prelude has already made well formed, so every unpaired
/// surrogate has become U+FFFD as `TextEncoder` requires.
fn utf8_encode<'js>(text: JsString<'js>) -> rquickjs::Result<TypedArray<'js, u8>> {
    let ctx = text.ctx().clone();
    TypedArray::new(ctx, text.to_string()?.into_bytes())
}

fn random_bytes<'js>(ctx: Ctx<'js>, length: usize) -> rquickjs::Result<TypedArray<'js, u8>> {
    use rand::Rng as _;
    if length > RANDOM_BYTES_LIMIT {
        return Err(Exception::throw_range(
            &ctx,
            "random byte requests are limited to 65,536 bytes",
        ));
    }
    let mut bytes = vec![0; length];
    rand::rng().fill_bytes(&mut bytes);
    TypedArray::new(ctx, bytes)
}

/// Routing metadata has its own transport allowance; the public budget counts only arguments.
fn validate_connector_request(request: &str, argument_limit: usize) -> rquickjs::Result<()> {
    let invalid = || {
        rquickjs::Error::new_from_js_message(
            "request",
            "connector call",
            "connector request exceeds the protocol limit or is invalid",
        )
    };
    if request.len() > limits().frame_bytes {
        return Err(invalid());
    }
    let value: Value = serde_json::from_str(request).map_err(|_| invalid())?;
    let empty_arguments = Value::Object(Default::default());
    let arguments = value.get("arguments").unwrap_or(&empty_arguments);
    let bytes = serde_json::to_vec(arguments).map_err(|_| invalid())?;
    if bytes.len() > argument_limit {
        return Err(invalid());
    }
    Ok(())
}

fn read_parent_frame(input: &mut impl BufRead) -> anyhow::Result<ParentFrame> {
    let mut line = String::new();
    let bytes = std::io::Read::take(input, (limits().parent_frame_bytes + 1) as u64)
        .read_line(&mut line)
        .context("read parent frame")?;
    if bytes == 0 {
        return Err(anyhow!("parent closed the runner channel"));
    }
    if bytes > limits().parent_frame_bytes || !line.ends_with('\n') {
        return Err(anyhow!("parent frame exceeds the protocol limit"));
    }
    serde_json::from_str(&line).context("decode parent frame")
}

fn write_runner_frame(output: &mut impl Write, frame: &RunnerFrame) -> anyhow::Result<()> {
    let encoded = encode_frame(frame).context("encode runner frame")?;
    output.write_all(&encoded).context("write runner frame")?;
    output.write_all(b"\n").context("terminate runner frame")?;
    output.flush().context("flush runner frame")
}

#[cfg(target_os = "linux")]
fn apply_confinement() -> anyhow::Result<()> {
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

    let allowlist: BTreeMap<i64, Vec<_>> = allowed_syscalls()
        .into_iter()
        .map(|syscall| (syscall, Vec::new()))
        .collect();
    let filter: BpfProgram = SeccompFilter::new(
        allowlist,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH
            .try_into()
            .context("unsupported runner architecture")?,
    )
    .context("compile runner syscall policy")?
    .try_into()
    .context("assemble runner syscall policy")?;
    seccompiler::apply_filter(&filter).context("install runner syscall policy")
}

#[cfg(target_os = "linux")]
fn allowed_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_brk,
        libc::SYS_clock_getres,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_close,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_fcntl,
        libc::SYS_fstat,
        libc::SYS_futex,
        libc::SYS_getpid,
        libc::SYS_getrandom,
        libc::SYS_getrusage,
        libc::SYS_gettid,
        libc::SYS_ioctl,
        libc::SYS_lseek,
        libc::SYS_madvise,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_mremap,
        libc::SYS_munmap,
        libc::SYS_nanosleep,
        libc::SYS_read,
        libc::SYS_readv,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sched_yield,
        libc::SYS_sigaltstack,
        libc::SYS_write,
        libc::SYS_writev,
    ]
}

#[cfg(not(target_os = "linux"))]
fn apply_confinement() -> anyhow::Result<()> {
    Err(anyhow!(
        "Code Mode execution requires Linux syscall confinement"
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::process_mode::codemode_protocol::{
        ConsoleEntry, CONSOLE_ENTRY_OVERHEAD_BYTES, MAX_FAILURE_MESSAGE_CHARS,
    };

    fn bindings(names: &[(&str, &str)]) -> Vec<RunnerBinding> {
        names
            .iter()
            .map(|(connector, operation)| RunnerBinding {
                connector: (*connector).to_owned(),
                operation: (*operation).to_owned(),
                call_id: format!("{connector}:{operation}"),
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn syscall_policy_excludes_filesystem_and_cross_process_control() {
        let syscalls = allowed_syscalls();
        assert!(!syscalls.contains(&libc::SYS_prlimit64));
        assert!(!syscalls.contains(&libc::SYS_newfstatat));
    }

    #[test]
    fn program_composes_connector_results_with_javascript_control_flow() {
        let result = execute_with(
            r#"
const first = connectors.email.first({value: "seed"});
const second = connectors.email.second({value: first.result});
return second.result === "two" ? {combined: [first.result, second.result]} : null;
"#,
            &bindings(&[("email", "first"), ("email", "second")]),
            |request| {
                let request: Value = serde_json::from_str(request).expect("connector request");
                let result = match request["call_id"].as_str().expect("connector call id") {
                    "email:first" => "one",
                    "email:second" => "two",
                    other => panic!("unexpected connector {other}"),
                };
                Ok(serde_json::json!({"ok": {"result": result}}).to_string())
            },
        )
        .expect("program executes");

        assert_eq!(result, serde_json::json!({"combined": ["one", "two"]}));
    }

    #[test]
    fn fresh_attempt_receives_the_bound_checkpoint_and_resume_input() {
        let resume = RunnerResumeContext {
            checkpoint: serde_json::json!({
                "prompt": "Choose a region",
                "state": {"candidate_ids": [1, 2]},
            }),
            input: serde_json::json!({"region": "west"}),
        };
        let result = execute_with_resume(
            "return execution.resume;",
            &[],
            ProgramData {
                resume: Some(&resume),
                ..ProgramData::default()
            },
            |_| unreachable!("program makes no connector calls"),
            |_| unreachable!("program does not pause"),
        )
        .expect("resumed program executes");

        assert_eq!(
            result,
            serde_json::json!({
                "checkpoint": {
                    "prompt": "Choose a region",
                    "state": {"candidate_ids": [1, 2]},
                },
                "input": {"region": "west"},
            })
        );
    }

    /// The point of the input channel: a program reads its arguments rather
    /// than having them edited into its text. This source is fixed and
    /// contains none of the values it returns.
    #[test]
    fn a_program_reads_its_arguments_from_the_input_channel() {
        let arguments = serde_json::json!({"owner": "bennight", "pr_number": 71});
        let result = execute_with_resume(
            "return {owner: execution.input.owner, pr: execution.input.pr_number};",
            &[],
            ProgramData {
                input: Some(&arguments),
                ..ProgramData::default()
            },
            |_| unreachable!("program makes no connector calls"),
            |_| unreachable!("program does not pause"),
        )
        .expect("program executes");

        assert_eq!(result, serde_json::json!({"owner": "bennight", "pr": 71}));
    }

    /// Input crosses the boundary as data. A value that reads like source
    /// arrives as the string it is, never as something the sandbox ran.
    #[test]
    fn input_that_looks_like_source_arrives_as_data() {
        let arguments = serde_json::json!({"hostile": "globalThis.leaked = 1;"});
        let result = execute_with_resume(
            "return {kind: typeof execution.input.hostile, value: execution.input.hostile};",
            &[],
            ProgramData {
                input: Some(&arguments),
                ..ProgramData::default()
            },
            |_| unreachable!("program makes no connector calls"),
            |_| unreachable!("program does not pause"),
        )
        .expect("program executes");

        assert_eq!(
            result,
            serde_json::json!({"kind": "string", "value": "globalThis.leaked = 1;"})
        );
    }

    #[test]
    fn pause_accepts_any_json_compatible_checkpoint_shape() {
        let observed = Arc::new(std::sync::Mutex::new(None));
        let observed_by_pause = observed.clone();
        let error = execute_with_resume(
            r#"execution.pause(["choose-region", {candidate_ids: [1, 2]}]);"#,
            &[],
            ProgramData::default(),
            |_| unreachable!("program makes no connector calls"),
            move |checkpoint| {
                *observed_by_pause.lock().expect("checkpoint lock") =
                    serde_json::from_str(checkpoint).ok();
                Err(rquickjs::Error::new_from_js_message(
                    "checkpoint",
                    "pause request",
                    "execution paused",
                ))
            },
        )
        .expect_err("test pause boundary stops evaluation");

        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
        assert_eq!(
            *observed.lock().expect("checkpoint lock"),
            Some(serde_json::json!([
                "choose-region",
                {"candidate_ids": [1, 2]},
            ]))
        );
    }

    #[test]
    fn artifact_emission_returns_the_parent_reference_to_the_program() {
        let observed = Arc::new(std::sync::Mutex::new(None));
        let observed_by_artifact = observed.clone();
        let result = execute_with_capabilities(
            r#"
const reference = execution.emitArtifact({kind: "preview", rows: [1, 2]});
return {
  artifactsAvailable: execution.artifactsAvailable,
  reference
};
"#,
            &[],
            ProgramData::default(),
            |_| unreachable!("program makes no connector calls"),
            |_| unreachable!("program does not pause"),
            move |value| {
                *observed_by_artifact.lock().expect("artifact lock") =
                    serde_json::from_str(value).ok();
                Ok(serde_json::json!({
                    "execution_id": "01900000-0000-7000-8000-000000000001",
                    "artifact_id": "01900000-0000-7000-8000-000000000002",
                })
                .to_string())
            },
            |_, _| Ok(()),
            true,
        )
        .expect("program emits an artifact");

        assert_eq!(
            *observed.lock().expect("artifact lock"),
            Some(serde_json::json!({
                "kind": "preview",
                "rows": [1, 2],
            }))
        );
        assert_eq!(result["artifactsAvailable"], true);
        assert_eq!(
            result["reference"]["artifact_id"],
            "01900000-0000-7000-8000-000000000002"
        );
    }

    #[test]
    fn artifact_api_reports_availability_without_narrowing_the_sdk_shape() {
        let result = execute_with(
            "return {available: execution.artifactsAvailable, emit: typeof execution.emitArtifact};",
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("program observes artifact availability");

        assert_eq!(
            result,
            serde_json::json!({
                "available": false,
                "emit": "function",
            })
        );
    }

    #[test]
    fn runtime_exposes_no_common_ambient_authority_apis() {
        let result = execute_with(
            "return {process: typeof process, fetch: typeof fetch, require: typeof require};",
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("program executes");

        assert_eq!(
            result,
            serde_json::json!({
                "process": "undefined",
                "fetch": "undefined",
                "require": "undefined"
            })
        );
    }

    #[test]
    fn fresh_runtime_does_not_share_javascript_state() {
        execute_with(
            r#"
globalThis.crossExecutionMarker = "global";
Object.prototype.crossExecutionMarker = "prototype";
return true;
"#,
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("first runtime executes");

        let result = execute_with(
            r#"
return {
  globalMarker: typeof globalThis.crossExecutionMarker,
  prototypeMarker: ({}).crossExecutionMarker ?? null
};
"#,
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("second runtime executes");

        assert_eq!(
            result,
            serde_json::json!({
                "globalMarker": "undefined",
                "prototypeMarker": null
            })
        );
    }

    #[test]
    fn runtime_exposes_only_generated_bindings_and_hides_raw_host_functions() {
        let result = execute_with(
            r#"
return {
  connectors: Object.keys(connectors),
  email: Object.keys(connectors.email),
  missing: typeof connectors.email.send,
  rawCall: typeof __gateway_call,
  rawMaterializing: typeof __gateway_connector_materializing,
  rawMaterialized: typeof __gateway_connector_materialized,
  rawBindings: typeof __gateway_bindings_json
};
"#,
            &bindings(&[("email", "read")]),
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("program executes");

        assert_eq!(
            result,
            serde_json::json!({
                "connectors": ["email"],
                "email": ["read"],
                "missing": "undefined",
                "rawCall": "undefined",
                "rawMaterializing": "undefined",
                "rawMaterialized": "undefined",
                "rawBindings": "undefined"
            })
        );
    }

    #[test]
    fn unavailable_binding_never_crosses_the_native_call_boundary() {
        let called = Arc::new(AtomicBool::new(false));
        let called_by_connector = called.clone();
        let error = execute_with(
            "return connectors.email.send({value: \"message\"});",
            &bindings(&[("email", "read")]),
            move |_| {
                called_by_connector.store(true, Ordering::SeqCst);
                unreachable!("unavailable binding must not call the host")
            },
        )
        .expect_err("unavailable binding is absent");

        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
    }

    // The in-code error contract: a refused connector call throws an Error
    // whose stable `code` is split from the broker's "code: message"
    // string, so programs branch on codes, never message text. Prefixes
    // that are not lowercase snake_case (an upstream message that merely
    // contains a colon) fall back to `connector_failure` with the full
    // text, and the thrown value stays a real Error even when the program
    // has replaced the global Error and string intrinsics.
    #[test]
    fn connector_refusals_throw_structured_errors_with_stable_codes() {
        let result = execute_with(
            r#"
globalThis.Error = function FakeError() { return {tampered: true}; };
String.prototype.indexOf = () => -1;
String.prototype.slice = () => "tampered";
Object.prototype.err = "inherited poison";
const outcomes = [];
for (const args of [{value: "first"}, {value: "second"}, {value: "third"}]) {
  try {
    outcomes.push({caught: false, ok: connectors.email.send(args)});
  } catch (error) {
    outcomes.push({caught: true, code: error.code, message: error.message});
  }
}
return outcomes;
"#,
            &bindings(&[("email", "send")]),
            {
                let call_index = AtomicU32::new(0);
                move |_| {
                    Ok(match call_index.fetch_add(1, Ordering::SeqCst) {
                        0 => serde_json::json!({ "err": "forbidden: forbid policies: hide-tool" }),
                        1 => serde_json::json!({ "err": "HTTP 500: upstream exploded" }),
                        // A success envelope: a poisoned Object.prototype.err
                        // must not turn it into a thrown failure.
                        _ => serde_json::json!({ "ok": {"result": "delivered"} }),
                    }
                    .to_string())
                }
            },
        )
        .expect("program handles the refusals");

        assert_eq!(
            result,
            serde_json::json!([
                {
                    "caught": true,
                    "code": "forbidden",
                    "message": "forbid policies: hide-tool",
                },
                {
                    "caught": true,
                    "code": "connector_failure",
                    "message": "HTTP 500: upstream exploded",
                },
                {
                    "caught": false,
                    "ok": {"result": "delivered"},
                },
            ])
        );
    }

    #[test]
    fn generated_binding_identity_ignores_program_serialization_hooks() {
        let result = execute_with(
            r#"
Object.prototype.toJSON = () => "mutated";
JSON.stringify = () => '{"call_id":"email:send","arguments":{}}';
return connectors.email.read({value: "inbox"}).result;
"#,
            &bindings(&[("email", "read")]),
            |request| {
                let request: Value = serde_json::from_str(request).expect("connector request");
                assert_eq!(request["call_id"], "email:read");
                Ok(r#"{"ok":{"result":"ok"}}"#.to_owned())
            },
        )
        .expect("generated binding identity stays immutable");

        assert_eq!(result, serde_json::json!("ok"));
    }

    #[test]
    fn oversized_connector_request_never_crosses_the_native_call_boundary() {
        let called = Arc::new(AtomicBool::new(false));
        let called_by_connector = called.clone();
        let error = execute_with(
            &format!(
                "return connectors.email.read({{value: \"x\".repeat({})}});",
                limits().request_bytes
            ),
            &bindings(&[("email", "read")]),
            move |_| {
                called_by_connector.store(true, Ordering::SeqCst);
                unreachable!("oversized request must be refused first")
            },
        )
        .expect_err("oversized connector request is refused");

        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
    }

    #[test]
    fn connector_argument_limit_excludes_routing_metadata() {
        for call_id in ["c", "a-longer-connector-binding-identifier"] {
            let request = serde_json::json!({"call_id": call_id, "arguments": {}}).to_string();
            validate_connector_request(&request, 2).expect("empty object fits exactly");
            assert!(validate_connector_request(&request, 1).is_err());
        }
        let size = limits().request_bytes - "{\"body\":\"\"}".len();
        let result = execute_with(
            &format!("return connectors.email.read({{body: 'x'.repeat({size})}});"),
            &bindings(&[("email", "read")]),
            |request| {
                let value: Value = serde_json::from_str(request).expect("request");
                assert_eq!(
                    serde_json::to_vec(&value["arguments"]).unwrap().len(),
                    limits().request_bytes
                );
                Ok("{\"ok\":true}".to_owned())
            },
        )
        .expect("the full argument allowance dispatches");
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn oversized_program_result_is_refused() {
        let error = execute_with(
            &format!("return \"x\".repeat({});", limits().result_bytes + 1),
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect_err("oversized result is refused");

        assert_eq!(error.code, RunnerFailureCode::ResultTooLarge);
    }

    #[test]
    fn non_json_program_result_has_a_stable_failure_code() {
        for source in [
            "return undefined;",
            "return 1n;",
            "const value = {}; value.self = value; return value;",
        ] {
            let error = execute_with(source, &[], |_| {
                unreachable!("program makes no connector calls")
            })
            .expect_err("program result is not JSON-compatible");

            assert_eq!(error.code, RunnerFailureCode::ResultNotJson);
        }
    }

    /// Arming moves the origin as well as the budget, so a program is granted
    /// its own time rather than what startup left over.
    ///
    /// The delay here is deliberately longer than the budget that follows it.
    /// If arming set only the duration, the elapsed startup would already
    /// exceed the grant and the interrupt would fire on the program's first
    /// check, so a program that finishes proves the origin moved. An assertion
    /// that merely watched a long program die would pass either way and prove
    /// nothing.
    #[test]
    #[ignore = "wall-clock integration check; run explicitly on an idle host (docs/testing.md)"]
    fn arming_grants_a_program_its_own_time_not_what_startup_left() {
        let (runtime, deadline_reached, deadline) =
            create_runtime_armable().expect("create runtime");

        let startup = Duration::from_millis(400);
        let budget_ms = 200;
        assert!(
            startup > Duration::from_millis(budget_ms),
            "the delay must exceed the grant, or this cannot tell the two apart"
        );
        std::thread::sleep(startup);
        deadline.arm(budget_ms);

        let context = JsContext::full(&runtime).expect("create context");
        let result = execute_in(
            &context,
            "let n = 0; for (let i = 0; i < 20000; i++) { n += i; } return n;",
            &[],
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program makes no connector calls")
                },
                pause: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program does not pause")
                },
                artifact: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program emits no artifacts")
                },
                wait: |_: f64| -> rquickjs::Result<String> {
                    unreachable!("program does not wait")
                },
                console: |_: ConsoleLevel, _: &str| -> rquickjs::Result<()> { Ok(()) },
                artifacts_available: false,
            },
            &deadline_reached,
        )
        .expect("a program armed after startup gets its full grant");
        assert!(result.is_number());
    }

    /// The armed budget is the one enforced, and its exhaustion is reported as
    /// a timeout rather than a program error.
    #[test]
    fn an_armed_budget_is_the_one_enforced() {
        let (runtime, deadline_reached, deadline) =
            create_runtime_armable().expect("create runtime");
        deadline.arm(20);

        let context = JsContext::full(&runtime).expect("create context");
        let error = execute_in(
            &context,
            "while (true) {}",
            &[],
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program makes no connector calls")
                },
                pause: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program does not pause")
                },
                artifact: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program emits no artifacts")
                },
                wait: |_: f64| -> rquickjs::Result<String> {
                    unreachable!("program does not wait")
                },
                console: |_: ConsoleLevel, _: &str| -> rquickjs::Result<()> { Ok(()) },
                artifacts_available: false,
            },
            &deadline_reached,
        )
        .expect_err("the armed budget terminates the program");
        assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout);
    }

    /// A program can pace itself without burning a core.
    ///
    /// The elapsed time is what makes this a wait rather than a no-op, and the
    /// program continuing afterwards is what makes it a wait rather than a
    /// termination.
    #[test]
    fn a_program_can_wait_and_then_continue() {
        let started = Instant::now();
        let result = execute_with("execution.wait(120); return \"resumed\";", &[], |_| {
            unreachable!("program makes no connector calls")
        })
        .expect("a paced program runs to completion");

        assert_eq!(result, Value::String("resumed".to_owned()));
        assert!(
            started.elapsed() >= Duration::from_millis(120),
            "the program must actually have waited"
        );
    }

    /// A wait far longer than the budget cannot outlive it, and ends as a
    /// timeout rather than as a program error.
    ///
    /// Those two reasons have opposite remedies — raise the limit, or read the
    /// code — so reporting the wrong one sends the reader in the wrong
    /// direction.
    #[test]
    #[ignore = "wall-clock wait latency; manual diagnostic only"]
    fn a_wait_longer_than_the_budget_is_clamped_and_reported_as_a_timeout() {
        let (runtime, deadline_reached, deadline) =
            create_runtime_armable().expect("create runtime");
        let budget = Duration::from_millis(200);
        deadline.arm(u64::try_from(budget.as_millis()).expect("budget fits"));

        let started = Instant::now();
        let context = JsContext::full(&runtime).expect("create context");
        let error = execute_in(
            &context,
            "try { execution.wait(60000); } catch {} return \"waited\";",
            &[],
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program makes no connector calls")
                },
                pause: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program does not pause")
                },
                artifact: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program emits no artifacts")
                },
                wait: runner_wait(deadline, deadline_reached.clone()),
                console: |_: ConsoleLevel, _: &str| -> rquickjs::Result<()> { Ok(()) },
                artifacts_available: false,
            },
            &deadline_reached,
        )
        .expect_err("a wait cannot outlive the budget that grants it");

        assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout);
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the wait must be clamped to the budget, not served in full"
        );
    }

    /// Catching an exhausted wait must not reopen any host capability.
    ///
    /// The final timeout result is not enough for side-effect safety: an
    /// admitted connector reached between the catch and that final check could
    /// already have changed external state.
    #[test]
    fn a_caught_exhausted_wait_cannot_reach_host_capabilities() {
        let (runtime, deadline_reached, deadline) =
            create_runtime_armable().expect("create runtime");
        deadline.arm(100);
        let connector_called = Arc::new(AtomicBool::new(false));
        let pause_called = Arc::new(AtomicBool::new(false));
        let artifact_called = Arc::new(AtomicBool::new(false));
        let connector_observed = connector_called.clone();
        let pause_observed = pause_called.clone();
        let artifact_observed = artifact_called.clone();

        let context = JsContext::full(&runtime).expect("create context");
        let error = execute_in(
            &context,
            r#"
try { execution.wait(60_000); } catch {}
try { connectors.test.effect({}); } catch {}
try { execution.emitArtifact({kind: "too-late"}); } catch {}
try { execution.pause({state: "too-late"}); } catch {}
return "too late";
"#,
            &bindings(&[("test", "effect")]),
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: move |_: &str| -> rquickjs::Result<String> {
                    connector_observed.store(true, Ordering::Relaxed);
                    Ok(serde_json::json!({"ok": Value::Null}).to_string())
                },
                pause: move |_: &str| -> rquickjs::Result<String> {
                    pause_observed.store(true, Ordering::Relaxed);
                    Ok("paused".to_owned())
                },
                artifact: move |_: &str| -> rquickjs::Result<String> {
                    artifact_observed.store(true, Ordering::Relaxed);
                    Ok(serde_json::json!({"artifact_id": "too-late"}).to_string())
                },
                wait: runner_wait(deadline, deadline_reached.clone()),
                console: |_: ConsoleLevel, _: &str| -> rquickjs::Result<()> { Ok(()) },
                artifacts_available: true,
            },
            &deadline_reached,
        )
        .expect_err("deadline exhaustion remains the terminal result");

        assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout);
        assert!(!connector_called.load(Ordering::Relaxed));
        assert!(!pause_called.load(Ordering::Relaxed));
        assert!(!artifact_called.load(Ordering::Relaxed));
    }

    /// The budget the operator granted still ends a program that waits inside
    /// a loop, so pacing cannot be turned into an unbounded run.
    #[test]
    fn repeated_waiting_still_ends_at_the_granted_budget() {
        let (runtime, deadline_reached, deadline) =
            create_runtime_armable().expect("create runtime");
        deadline.arm(300);

        let context = JsContext::full(&runtime).expect("create context");
        let error = execute_in(
            &context,
            // Each wait is small enough to be granted, so the program is
            // stopped by the budget rather than by any single refusal.
            "while (true) { execution.wait(20); }",
            &[],
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program makes no connector calls")
                },
                pause: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program does not pause")
                },
                artifact: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program emits no artifacts")
                },
                wait: runner_wait(deadline, deadline_reached.clone()),
                console: |_: ConsoleLevel, _: &str| -> rquickjs::Result<()> { Ok(()) },
                artifacts_available: false,
            },
            &deadline_reached,
        )
        .expect_err("a program that only waits is still bounded by its budget");

        assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout);
    }

    /// A wait that is not a number of milliseconds is refused rather than
    /// coerced into some other duration.
    #[test]
    fn a_nonsensical_wait_is_refused() {
        for argument in ["-1", "NaN", "Infinity"] {
            let result = execute_with(
                &format!("try {{ execution.wait({argument}); return \"waited\"; }} catch (e) {{ return e.code; }}"),
                &[],
                |_| unreachable!("program makes no connector calls"),
            )
            .expect("the refusal reaches the program as a catchable error");
            assert_eq!(
                result,
                Value::String("execution_wait_invalid".to_owned()),
                "wait({argument}) must be refused"
            );
        }
    }

    #[test]
    fn infinite_loop_has_the_stable_timeout_code() {
        let (runtime, deadline_reached) =
            create_runtime_with_limit(Duration::from_millis(10)).expect("create runtime");
        let context = JsContext::full(&runtime).expect("create context");
        let error = execute_in(
            &context,
            "while (true) {}",
            &[],
            None,
            &Value::Null,
            ExecutionCapabilities {
                call: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program makes no connector calls")
                },
                pause: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program does not pause")
                },
                artifact: |_: &str| -> rquickjs::Result<String> {
                    unreachable!("program emits no artifacts")
                },
                wait: |_: f64| -> rquickjs::Result<String> {
                    unreachable!("program does not wait")
                },
                console: |_: ConsoleLevel, _: &str| -> rquickjs::Result<()> { Ok(()) },
                artifacts_available: false,
            },
            &deadline_reached,
        )
        .expect_err("interrupt deadline terminates the program");

        assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout);
    }

    #[test]
    fn memory_pressure_terminates_with_a_stable_program_failure() {
        let error = execute_with(
            "const chunks = []; while (true) { chunks.push(new ArrayBuffer(1024 * 1024)); }",
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect_err("runtime memory limit terminates the program");

        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
    }

    #[test]
    fn connector_object_graph_pressure_uses_the_connector_limit_failure() {
        let binding = RunnerBinding {
            connector: "mock".to_owned(),
            operation: "read".to_owned(),
            call_id: "call-1".to_owned(),
        };
        let expansive = format!(
            "{{\"ok\":[{}]}}",
            "{},".repeat(limits().heap_bytes / 32) + "{}"
        );

        let error = execute_with("return connectors.mock.read({});", &[binding], move |_| {
            Ok(expansive.clone())
        })
        .expect_err("connector object graph must hit the QuickJS heap boundary");

        assert_eq!(error.code, RunnerFailureCode::ConnectorResultTooLarge);
    }

    #[test]
    fn native_connector_failure_is_not_mislabeled_as_materialization_pressure() {
        let error = execute_with(
            "return connectors.mock.read({});",
            &[RunnerBinding {
                connector: "mock".to_owned(),
                operation: "read".to_owned(),
                call_id: "call-1".to_owned(),
            }],
            |_| {
                Err(rquickjs::Error::new_from_js_message(
                    "response",
                    "connector call",
                    "connector transport failed",
                ))
            },
        )
        .expect_err("native connector transport failure must stop evaluation");

        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
    }

    #[test]
    fn matching_user_exception_message_is_not_a_connector_limit_failure() {
        let error = execute_with(
            &format!("throw new Error({CONNECTOR_MATERIALIZATION_FAILURE:?});"),
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect_err("user exception stops evaluation");

        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
    }

    #[test]
    fn program_failure_message_is_bounded() {
        let error = RunnerExecutionFailure::new(
            RunnerFailureCode::ProgramFailed,
            "x".repeat(MAX_FAILURE_MESSAGE_CHARS * 2),
        );

        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
        assert_eq!(error.message.chars().count(), MAX_FAILURE_MESSAGE_CHARS);
    }

    type HostCall = fn(&str) -> rquickjs::Result<String>;
    type HostWait = fn(f64) -> rquickjs::Result<String>;
    type HostConsole = fn(ConsoleLevel, &str) -> rquickjs::Result<()>;

    fn unused_capabilities(
    ) -> ExecutionCapabilities<HostCall, HostCall, HostCall, HostWait, HostConsole> {
        ExecutionCapabilities {
            call: |_: &str| -> rquickjs::Result<String> {
                unreachable!("program makes no connector calls")
            },
            pause: |_: &str| -> rquickjs::Result<String> { unreachable!("program does not pause") },
            artifact: |_: &str| -> rquickjs::Result<String> {
                unreachable!("program emits no artifacts")
            },
            wait: |_: f64| -> rquickjs::Result<String> { unreachable!("program does not wait") },
            console: |_: ConsoleLevel, _: &str| -> rquickjs::Result<()> { Ok(()) },
            artifacts_available: false,
        }
    }

    fn program_failure(source: &str) -> String {
        let error = execute_with(source, &[], |_| {
            unreachable!("program makes no connector calls")
        })
        .expect_err("program fails");
        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
        error.message
    }

    #[test]
    fn a_program_body_can_await_connector_results_and_promises() {
        let result = execute_with(
            r#"
const first = await connectors.email.first({});
const doubled = await Promise.resolve(first.result * 2);
return {first: first.result, doubled};
"#,
            &bindings(&[("email", "first")]),
            |_| Ok(serde_json::json!({"ok": {"result": 21}}).to_string()),
        )
        .expect("an awaiting program completes");

        assert_eq!(result, serde_json::json!({"first": 21, "doubled": 42}));
    }

    /// A promise the program returns is the result's value once settled, not
    /// the promise object, which serializes as an empty object.
    #[test]
    fn a_returned_promise_settles_to_its_value() {
        let result = execute_with("return (async () => ({answer: 5}))();", &[], |_| {
            unreachable!("program makes no connector calls")
        })
        .expect("the returned promise settles");

        assert_eq!(result, serde_json::json!({"answer": 5}));
    }

    #[test]
    fn an_awaited_connector_refusal_keeps_its_stable_code() {
        let refuse = |_: &str| Ok(serde_json::json!({"err": "forbidden: hidden"}).to_string());
        let caught = execute_with(
            r#"
try {
  await connectors.email.send({});
  return "sent";
} catch (error) {
  return error.code;
}
"#,
            &bindings(&[("email", "send")]),
            refuse,
        )
        .expect("the program handles the refusal");
        assert_eq!(caught, Value::String("forbidden".to_owned()));

        let error = execute_with(
            "await connectors.email.send({}); return \"sent\";",
            &bindings(&[("email", "send")]),
            refuse,
        )
        .expect_err("an unhandled refusal rejects the program");
        assert_eq!(error.code, RunnerFailureCode::ProgramFailed);
        assert!(error.message.contains("Error: hidden"), "{}", error.message);
    }

    #[test]
    fn a_promise_that_can_never_settle_fails_instead_of_returning() {
        for source in [
            "await new Promise(() => {}); return 1;",
            "return new Promise(() => {});",
        ] {
            let message = program_failure(source);
            assert!(message.contains("never finished"), "{source}: {message}");
        }
    }

    #[test]
    fn the_deadline_bounds_promise_jobs() {
        for source in [
            "await null; while (true) {}",
            "const spin = () => Promise.resolve().then(spin); spin(); \
             await new Promise(() => {});",
        ] {
            let (runtime, deadline_reached) =
                create_runtime_with_limit(Duration::from_millis(50)).expect("create runtime");
            let context = JsContext::full(&runtime).expect("create context");
            let error = execute_in(
                &context,
                source,
                &[],
                None,
                &Value::Null,
                unused_capabilities(),
                &deadline_reached,
            )
            .expect_err("the deadline ends promise jobs");

            assert_eq!(error.code, RunnerFailureCode::ExecutionTimeout, "{source}");
        }
    }

    #[test]
    fn failures_report_positions_in_the_submitted_program() {
        assert_eq!(
            program_failure(
                "const a = 1;\nfunction decode() {\n  return new MissingDecoder().decode(a);\n}\n\
                 return decode();"
            ),
            "Code Mode program evaluation failed: ReferenceError: MissingDecoder is not defined\n    \
             at decode (program:3:14)\n    at <anonymous> (program:5:8)"
        );
        assert_eq!(
            program_failure("await null;\nnull.property;"),
            "Code Mode program evaluation failed: TypeError: cannot read property 'property' of \
             null\n    at <anonymous> (program:2:1)"
        );
        assert_eq!(
            program_failure("const first = 1;\nconst x = ;\nreturn x;"),
            "Code Mode program evaluation failed: SyntaxError: unexpected token in expression: \
             ';'\n    at program:2"
        );
        let unterminated = program_failure("return {\n  open: true,");
        assert!(
            unterminated.starts_with("Code Mode program evaluation failed: SyntaxError: ")
                && unterminated.ends_with("\n    at the end of the program"),
            "{unterminated}"
        );
    }

    #[test]
    fn connector_failures_point_at_the_calling_line_not_gateway_code() {
        let error = execute_with(
            "const unused = 1;\nreturn connectors.email.send({});",
            &bindings(&[("email", "send")]),
            |_| Ok(serde_json::json!({"err": "forbidden: hidden"}).to_string()),
        )
        .expect_err("the refusal fails the program");

        assert!(
            error.message.starts_with(
                "Code Mode program evaluation failed: Error: hidden\n    at <anonymous> (program:2:"
            ),
            "{}",
            error.message
        );
        assert!(
            !error.message.contains(ENGINE_SCRIPT_NAME),
            "{}",
            error.message
        );
    }

    /// A thrown value that is not an Error is described without running any of
    /// the program's code, even code the value itself supplies.
    #[test]
    fn thrown_non_error_values_are_described_without_running_program_code() {
        assert_eq!(
            program_failure("throw 'plain string';"),
            "Code Mode program evaluation failed: uncaught string: plain string"
        );
        assert_eq!(
            program_failure("throw 42;"),
            "Code Mode program evaluation failed: uncaught number: 42"
        );
        assert_eq!(
            program_failure("throw null;"),
            "Code Mode program evaluation failed: uncaught null"
        );
        let called = Arc::new(AtomicBool::new(false));
        let called_by_connector = called.clone();
        let error = execute_with(
            "throw {toString() { connectors.email.send({}); return 'shown'; }, \
             toJSON() { connectors.email.send({}); return 'shown'; }};",
            &bindings(&[("email", "send")]),
            move |_| {
                called_by_connector.store(true, Ordering::SeqCst);
                Ok(serde_json::json!({"ok": null}).to_string())
            },
        )
        .expect_err("the thrown object fails the program");

        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(
            error.message,
            "Code Mode program evaluation failed: uncaught object; throw an Error to report a \
             message and position"
        );
    }

    #[test]
    fn engine_stack_frames_are_restated_in_program_positions() {
        let layout = ProgramLayout {
            first_line: 10,
            last_line: 12,
        };
        assert_eq!(
            layout.program_stack(
                "    at f (eval_script:11:4)\n    at <anonymous> (eval_script:3:1)\n    at parse \
                 (native)\n    at <eval> (eval_script:14:2)"
            ),
            "    at f (program:2:4)\n    at parse (native)"
        );
        assert_eq!(
            layout.program_stack("    at eval_script:12:40"),
            "    at program:3"
        );
        assert_eq!(
            layout.program_stack("    at eval_script:13:9"),
            "    at the end of the program"
        );
    }

    #[test]
    fn line_breaks_are_counted_as_the_engine_counts_them() {
        assert_eq!(engine_line_breaks("a\nb\n"), 2);
        assert_eq!(engine_line_breaks("a\r\nb"), 1);
        assert_eq!(engine_line_breaks("a\rb"), 1);
        assert_eq!(engine_line_breaks("a\u{2028}b\u{2029}c"), 2);
        for separator in ["\n", "\r", "\r\n", "\u{2028}", "\u{2029}"] {
            let message = program_failure(&format!(
                "const a = 1;{separator}return new MissingDecoder(a);"
            ));
            assert!(
                message.ends_with("\n    at <anonymous> (program:2:12)"),
                "{separator:?}: {message}"
            );
        }
    }

    /// Reporting a failure reads the thrown value, and a getter or proxy can
    /// run program code during that read. None of it may reach a connector.
    #[test]
    fn reporting_a_failure_cannot_reach_host_capabilities() {
        for source in [
            "throw { get code() { connectors.email.send({}); return 'forbidden'; } };",
            "throw new Proxy({}, { get() { connectors.email.send({}); return undefined; } });",
            "const error = new Error('quiet');\nObject.defineProperty(error, 'message', \
             { get() { connectors.email.send({}); return 'loud'; } });\nthrow error;",
            "const error = new Error('quiet');\nObject.defineProperty(error, 'name', \
             { get() { connectors.email.send({}); return 'LoudError'; } });\nthrow error;",
        ] {
            let called = Arc::new(AtomicBool::new(false));
            let called_by_connector = called.clone();
            let error = execute_with(source, &bindings(&[("email", "send")]), move |_| {
                called_by_connector.store(true, Ordering::SeqCst);
                Ok(serde_json::json!({"ok": null}).to_string())
            })
            .expect_err("the thrown value fails the program");

            assert!(!called.load(Ordering::SeqCst), "{source}");
            assert_eq!(error.code, RunnerFailureCode::ProgramFailed, "{source}");
        }
    }

    /// Run a program and return what it printed alongside its outcome.
    fn execute_capturing_console(
        source: &str,
    ) -> (Result<Value, RunnerExecutionFailure>, Vec<ConsoleEntry>) {
        let printed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = printed.clone();
        let outcome = execute_with_capabilities(
            source,
            &[],
            ProgramData::default(),
            |_| unreachable!("program makes no connector calls"),
            |_| unreachable!("program does not pause"),
            |_| unreachable!("program emits no artifacts"),
            move |level, text| {
                sink.lock().expect("console sink").push(ConsoleEntry {
                    level,
                    text: text.to_owned(),
                });
                Ok(())
            },
            false,
        );
        let printed = printed.lock().expect("console sink").clone();
        (outcome, printed)
    }

    fn printed_lines(source: &str) -> Vec<String> {
        let (outcome, printed) = execute_capturing_console(source);
        outcome.expect("program completes");
        printed.into_iter().map(|entry| entry.text).collect()
    }

    #[test]
    fn console_methods_exist_and_never_end_a_program() {
        let (outcome, printed) = execute_capturing_console(
            r#"
const names = ["log", "info", "debug", "warn", "error", "trace", "dir", "dirxml", "table",
  "assert", "count", "countReset", "group", "groupCollapsed", "groupEnd", "time", "timeLog",
  "timeEnd"];
const hostile = new Proxy({}, { ownKeys() { throw new Error("no keys"); } });
for (const name of names) {
  console[name]();
  console[name](hostile, undefined, Symbol("s"));
}
return names.filter((name) => typeof console[name] !== "function");
"#,
        );
        assert_eq!(
            outcome.expect("console calls never throw"),
            serde_json::json!([])
        );
        assert!(printed.iter().any(|entry| entry
            .text
            .contains("[console could not format a value: no keys]")));
    }

    #[test]
    fn console_formats_values_close_to_node() {
        assert_eq!(
            printed_lines(
                r#"
console.log("plain", 1, -0, true, null, undefined, 2n, Symbol("s"));
console.log({a: 1, b: "x", c: [1, "two", {d: null}]});
const loop = {name: "loop"};
loop.self = loop;
console.log(loop);
console.log(new Map([["k", 1]]), new Set([1, 2]), new Date(0), /a+/g);
console.log(new Uint8Array([1, 2]), new ArrayBuffer(3), function named() {}, () => {});
console.log("%s has %d items (%i%%) %o %j", "list", 3.5, 42.9, {a: 1}, {b: [2]});
console.log("%s:", "key", "value");
console.log("%cstyled", "color: red");
console.log("100%");
console.log("%s");
console.log(new URL("https://example.com/a"), { link: new URL("https://example.com/b") });
return null;
"#
            ),
            vec![
                "plain 1 -0 true null undefined 2n Symbol(s)",
                r#"{"a": 1, "b": "x", "c": [1, "two", {"d": null}]}"#,
                r#"{"name": "loop", "self": [Circular]}"#,
                r#"Map(1) {"k" => 1} Set(2) {1, 2} 1970-01-01T00:00:00.000Z /a+/g"#,
                "Uint8Array(2) [1, 2] ArrayBuffer { byteLength: 3 } [Function: named] \
                 [Function: anonymous]",
                r#"list has 3.5 items (42%) {"a": 1} {"b":[2]}"#,
                "key: value",
                "styled",
                "100%",
                "%s",
                r#"https://example.com/a {"link": "https://example.com/b"}"#,
            ]
        );
    }

    #[test]
    fn console_errors_report_program_positions() {
        let lines = printed_lines(
            "const error = new TypeError('bad input');\nconsole.error(error);\nreturn null;",
        );
        assert_eq!(
            lines,
            vec!["TypeError: bad input\n    at <anonymous> (program:1:19)"]
        );
    }

    #[test]
    fn console_levels_counters_groups_and_timers() {
        let (outcome, printed) = execute_capturing_console(
            r#"
console.debug("d");
console.info("i");
console.warn("w");
console.error("e");
console.assert(true, "hidden");
console.assert(false, "count %s", "x");
console.trace("here");
console.count();
console.count();
console.count("a");
console.countReset("a");
console.count("a");
console.group("outer");
console.log("inner\nsecond");
console.groupEnd();
console.groupEnd();
console.log("after");
console.time("t");
console.timeEnd("t");
console.timeEnd("missing");
return null;
"#,
        );
        outcome.expect("program completes");
        let summary: Vec<(ConsoleLevel, String)> = printed
            .into_iter()
            .map(|entry| (entry.level, entry.text))
            .collect();
        assert_eq!(summary[0], (ConsoleLevel::Debug, "d".to_owned()));
        assert_eq!(summary[1], (ConsoleLevel::Info, "i".to_owned()));
        assert_eq!(summary[2], (ConsoleLevel::Warn, "w".to_owned()));
        assert_eq!(summary[3], (ConsoleLevel::Error, "e".to_owned()));
        assert_eq!(
            summary[4],
            (ConsoleLevel::Error, "Assertion failed: count x".to_owned())
        );
        assert_eq!(summary[5].0, ConsoleLevel::Error);
        assert!(
            summary[5]
                .1
                .starts_with("Trace: here\n    at <anonymous> (program:8:"),
            "{}",
            summary[5].1
        );
        assert!(
            !summary[5].1.contains(ENGINE_SCRIPT_NAME),
            "{}",
            summary[5].1
        );
        let texts: Vec<&str> = summary[6..].iter().map(|(_, text)| text.as_str()).collect();
        assert_eq!(
            texts[..7],
            [
                "default: 1",
                "default: 2",
                "a: 1",
                "a: 1",
                "outer",
                "  inner\n  second",
                "after"
            ]
        );
        let timed = texts[7];
        assert!(timed.starts_with("t: ") && timed.ends_with("ms"), "{timed}");
        assert_eq!(summary.last().expect("timer warning").0, ConsoleLevel::Warn);
        assert_eq!(texts[8], "Timer \"missing\" does not exist");
    }

    /// Formatting stops once a call's text passes the console budget, so a
    /// huge value costs no more than the output that can be kept.
    #[test]
    fn console_formatting_stops_at_the_console_budget() {
        let lines = printed_lines(
            "console.log(Array.from({length: 2_000_000}, (_, index) => index)); return null;",
        );
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].len() <= limits().console_bytes + 16,
            "{}",
            lines[0].len()
        );
        assert!(lines[0].starts_with("[0, 1, 2, "));
    }

    /// The parent learns of truncation from the runner, because an entry the
    /// runner cut to fit also fits the parent's identical budget exactly.
    #[test]
    fn console_frames_report_truncation_once() {
        let mut exact = ConsoleCapture::new(CONSOLE_ENTRY_OVERHEAD_BYTES + 4);
        let frames = console_frames(&mut exact, ConsoleLevel::Log, "abcd");
        assert!(matches!(
            frames.as_slice(),
            [RunnerFrame::Console { text, .. }] if text == "abcd"
        ));
        assert!(matches!(
            console_frames(&mut exact, ConsoleLevel::Log, "dropped").as_slice(),
            [RunnerFrame::ConsoleTruncated]
        ));
        assert!(console_frames(&mut exact, ConsoleLevel::Log, "silent").is_empty());

        let mut cut = ConsoleCapture::new(CONSOLE_ENTRY_OVERHEAD_BYTES + 2);
        assert!(matches!(
            console_frames(&mut cut, ConsoleLevel::Warn, "abcd").as_slice(),
            [RunnerFrame::Console { text, .. }, RunnerFrame::ConsoleTruncated] if text == "ab"
        ));
    }

    #[test]
    fn console_methods_with_unprintable_labels_never_end_a_program() {
        let (outcome, _) = execute_capturing_console(
            r#"
const bare = Object.create(null);
const hostile = { toString() { throw new Error("no text"); } };
console.count(bare);
console.countReset(bare);
console.time(hostile);
console.timeLog(hostile);
console.timeEnd(hostile);
console.group(bare);
console.groupEnd();
return "finished";
"#,
        );
        assert_eq!(
            outcome.expect("console labels never end a program"),
            Value::String("finished".to_owned())
        );
    }

    /// Large strings, nested strings, long templates and `%j` all stop at the
    /// console budget instead of formatting the whole input.
    #[test]
    fn console_formatting_is_bounded_for_every_large_input() {
        let limit = limits().console_bytes;
        let lines = printed_lines(&format!(
            r#"
const huge = "x".repeat({big});
console.log(huge);
console.log({{ nested: huge }});
console.log("%s " + huge, "tail");
console.log("%j", Array.from({{ length: 200000 }}, (_, index) => ({{ index }})));
return null;
"#,
            big = limit * 4
        ));
        assert_eq!(lines.len(), 4);
        for line in &lines {
            assert!(line.len() <= limit + 1, "{}", line.len());
        }
        assert!(
            lines[1].starts_with(r#"{"nested": "xxx"#),
            "{}",
            &lines[1][..40]
        );
        assert!(
            lines[3].starts_with(r#"[{"index": 0}, {"index": 1}"#),
            "{}",
            &lines[3][..40]
        );
    }

    /// Printed text is kept as written; only error stacks are restated in
    /// program positions.
    #[test]
    fn console_keeps_printed_text_as_written() {
        assert_eq!(
            printed_lines(
                "console.log('value\\r\\n', 'at eval_script:1', '    at f (eval_script:2:3)'); return null;"
            ),
            vec!["value\r\n at eval_script:1     at f (eval_script:2:3)"]
        );
    }

    /// Group indentation counts against the console budget, however deep the
    /// groups and however many lines the text has.
    #[test]
    fn console_group_indentation_stays_within_the_budget() {
        let lines = printed_lines(
            "for (let index = 0; index < 2000; index += 1) console.group();\n\
             console.log('\\n'.repeat(65535));\nreturn null;",
        );
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].len() <= limits().console_bytes + 1,
            "{}",
            lines[0].len()
        );
    }

    #[test]
    fn console_trace_substitutes_and_timers_keep_their_start() {
        let (outcome, printed) = execute_capturing_console(
            r#"
console.trace("item %d", 3);
console.time("t");
console.time("t");
console.log({ get value() { throw new Error("x".repeat(1_000_000)); } });
return null;
"#,
        );
        outcome.expect("program completes");
        assert!(
            printed[0].text.starts_with("Trace: item 3\n"),
            "{}",
            printed[0].text
        );
        assert_eq!(
            (printed[1].level, printed[1].text.as_str()),
            (ConsoleLevel::Warn, "Timer \"t\" already exists")
        );
        assert!(
            printed[2].text.len() <= limits().console_bytes + 1,
            "{}",
            printed[2].text.len()
        );
        assert!(printed[2]
            .text
            .starts_with("{\"value\":  [console could not format a value: xxx"));
    }

    #[test]
    fn undeliverable_console_output_does_not_end_a_program() {
        let result = execute_with_capabilities(
            "console.log('lost'); return 'finished';",
            &[],
            ProgramData::default(),
            |_| unreachable!("program makes no connector calls"),
            |_| unreachable!("program does not pause"),
            |_| unreachable!("program emits no artifacts"),
            |_, _| {
                Err(rquickjs::Error::new_from_js_message(
                    "console",
                    "console output",
                    "console transport failed",
                ))
            },
            false,
        )
        .expect("console failures are swallowed");
        assert_eq!(result, Value::String("finished".to_owned()));
    }

    fn evaluate(source: &str) -> Value {
        execute_with(source, &[], |_| {
            unreachable!("program makes no connector calls")
        })
        .expect("program completes")
    }

    #[test]
    fn text_decoder_turns_base64_file_content_into_text() {
        assert_eq!(
            evaluate(
                "return new TextDecoder().decode(Uint8Array.fromBase64('aMOpbGxvIOKckyDwn5iA'));"
            ),
            Value::String("héllo ✓ 😀".to_owned())
        );
    }

    #[test]
    fn text_decoder_replaces_or_rejects_invalid_bytes() {
        assert_eq!(
            evaluate(
                r#"
const decoder = new TextDecoder();
let fatal;
try {
  new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array([0x61, 0xff]));
} catch (error) {
  fatal = `${error.name}: ${error.message}`;
}
return {
  replaced: decoder.decode(new Uint8Array([0x61, 0xff, 0x62])),
  maximalSubpart: decoder.decode(new Uint8Array([0xe2, 0x82, 0x41])),
  truncatedEnd: decoder.decode(new Uint8Array([0x61, 0xe2, 0x82])),
  fatal,
};
"#
            ),
            serde_json::json!({
                "replaced": "a\u{fffd}b",
                "maximalSubpart": "\u{fffd}A",
                "truncatedEnd": "a\u{fffd}",
                "fatal": "TypeError: The encoded data was not valid UTF-8",
            })
        );
    }

    #[test]
    fn text_decoder_handles_byte_order_marks_and_streams() {
        assert_eq!(
            evaluate(
                r#"
const streaming = new TextDecoder();
const split = streaming.decode(new Uint8Array([0x61, 0xe2, 0x82]), { stream: true });
const joined = split + streaming.decode(new Uint8Array([0xac, 0x62]));
const bom = new TextDecoder();
const splitBom = bom.decode(new Uint8Array([0xef, 0xbb]), { stream: true }) +
  bom.decode(new Uint8Array([0xbf, 0x63]));
return {
  split,
  joined,
  stripped: new TextDecoder().decode(new Uint8Array([0xef, 0xbb, 0xbf, 0x61])),
  kept: new TextDecoder("utf-8", { ignoreBOM: true })
    .decode(new Uint8Array([0xef, 0xbb, 0xbf, 0x61])),
  splitBom,
  fromBuffer: new TextDecoder().decode(new Uint8Array([0x6f, 0x6b]).buffer),
  fromView: new TextDecoder().decode(new DataView(new Uint8Array([0x78, 0x6f, 0x6b]).buffer, 1)),
};
"#
            ),
            serde_json::json!({
                "split": "a",
                "joined": "a€b",
                "stripped": "a",
                "kept": "\u{feff}a",
                "splitBom": "c",
                "fromBuffer": "ok",
                "fromView": "ok",
            })
        );
    }

    #[test]
    fn text_decoder_accepts_only_utf8_labels() {
        assert_eq!(
            evaluate(
                r#"
let refused;
try {
  new TextDecoder("latin1");
} catch (error) {
  refused = error.name;
}
const decoder = new TextDecoder(" UTF8 ", { fatal: 1 });
return { encoding: decoder.encoding, fatal: decoder.fatal, ignoreBOM: decoder.ignoreBOM, refused };
"#
            ),
            serde_json::json!({
                "encoding": "utf-8",
                "fatal": true,
                "ignoreBOM": false,
                "refused": "RangeError",
            })
        );
    }

    #[test]
    fn text_encoder_encodes_and_fills_destinations() {
        assert_eq!(
            evaluate(
                r#"
const encoder = new TextEncoder();
const destination = new Uint8Array(5);
const into = encoder.encodeInto("a€😀", destination);
return {
  encoded: Array.from(encoder.encode("é😀")),
  unpaired: Array.from(encoder.encode("\uD800")),
  into,
  destination: Array.from(destination),
  roundTrip: new TextDecoder().decode(encoder.encode("½ ✓")),
};
"#
            ),
            serde_json::json!({
                "encoded": [0xc3, 0xa9, 0xf0, 0x9f, 0x98, 0x80],
                "unpaired": [0xef, 0xbf, 0xbd],
                "into": {"read": 2, "written": 4},
                "destination": [0x61, 0xe2, 0x82, 0xac, 0],
                "roundTrip": "½ ✓",
            })
        );
    }

    #[test]
    fn crypto_produces_random_uuids_and_values() {
        let result = evaluate(
            r#"
const first = crypto.randomUUID();
const second = crypto.randomUUID();
const words = new Uint32Array(8);
const errorName = (call) => {
  try {
    call();
    return null;
  } catch (error) {
    return `${error.name}:${error instanceof DOMException}`;
  }
};
return {
  format: /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(first),
  distinct: first !== second,
  sameArray: crypto.getRandomValues(words) === words,
  filled: words.some((word) => word !== 0),
  bigints: crypto.getRandomValues(new BigUint64Array(2)).length,
  floats: errorName(() => crypto.getRandomValues(new Float32Array(1))),
  quota: errorName(() => crypto.getRandomValues(new Uint8Array(65537))),
  largest: crypto.getRandomValues(new Uint8Array(65536)).length,
};
"#,
        );
        assert_eq!(
            result,
            serde_json::json!({
                "format": true,
                "distinct": true,
                "sameArray": true,
                "filled": true,
                "bigints": 2,
                "floats": "TypeMismatchError:true",
                "quota": "QuotaExceededError:true",
                "largest": 65536,
            })
        );
    }

    #[test]
    fn structured_clone_copies_standard_types_and_shared_references() {
        assert_eq!(
            evaluate(
                r#"
const shared = { label: "shared" };
const loop = { name: "loop" };
loop.self = loop;
class Point { constructor() { this.x = 1; } norm() { return 1; } }
const source = {
  shared, again: shared, loop,
  date: new Date(0), pattern: /a+/gi, map: new Map([["k", shared]]), set: new Set([1, 2]),
  bytes: new Uint8Array([1, 2, 3]), view: new DataView(new ArrayBuffer(2)), big: 10n,
  boxed: Object("text"), error: new RangeError("too far"), point: new Point(),
  sparse: [1, , 3],
};
const copy = structuredClone(source);
return {
  sharedKept: copy.shared === copy.again && copy.shared !== shared,
  cycleKept: copy.loop.self === copy.loop,
  date: copy.date instanceof Date && copy.date.getTime() === 0,
  pattern: `${copy.pattern}`,
  mapValueShared: copy.map.get("k") === copy.shared,
  set: [...copy.set],
  bytes: Array.from(copy.bytes),
  independentBytes: copy.bytes.buffer !== source.bytes.buffer,
  view: copy.view instanceof DataView && copy.view.byteLength,
  big: typeof copy.big,
  boxed: copy.boxed instanceof String && copy.boxed.valueOf(),
  error: copy.error instanceof RangeError && copy.error.message,
  pointMethods: typeof copy.point.norm,
  pointX: copy.point.x,
  sparse: Object.keys(copy.sparse),
};
"#
            ),
            serde_json::json!({
                "sharedKept": true,
                "cycleKept": true,
                "date": true,
                "pattern": "/a+/gi",
                "mapValueShared": true,
                "set": [1, 2],
                "bytes": [1, 2, 3],
                "independentBytes": true,
                "view": 2,
                "big": "bigint",
                "boxed": "text",
                "error": "too far",
                "pointMethods": "undefined",
                "pointX": 1,
                "sparse": ["0", "2"],
            })
        );
    }

    /// A value's own properties cannot stand in for the built-ins a clone, a
    /// transfer, or a decode reads it through.
    #[test]
    fn helpers_read_values_through_built_ins_not_own_properties() {
        assert_eq!(
            evaluate(
                r#"
const buffer = new ArrayBuffer(4);
new Uint8Array(buffer)[0] = 9;
buffer.slice = () => buffer;
const bytes = new Uint8Array([1, 2]);
Object.defineProperty(bytes, "buffer", { value: new ArrayBuffer(0) });
const date = new Date(5);
date.getTime = () => 0;
const pattern = /a/g;
Object.defineProperty(pattern, "source", { value: "b" });
Object.defineProperty(pattern, "flags", { value: "" });
const map = new Map([[1, 2]]);
map.entries = () => [][Symbol.iterator]();
map[Symbol.iterator] = function* () {};
const moved = new ArrayBuffer(2);
moved.transfer = () => moved;
const copy = structuredClone({ buffer, bytes, date, pattern, map, moved }, { transfer: [moved] });
const view = new Uint8Array([0x6f, 0x6b]);
Object.defineProperty(view, "byteLength", { value: 0 });
return {
  bufferIndependent: copy.buffer !== buffer && new Uint8Array(copy.buffer)[0] === 9,
  bytes: Array.from(copy.bytes),
  date: copy.date.getTime(),
  pattern: `${copy.pattern}`,
  map: [...copy.map],
  movedDetached: moved.detached,
  movedCopy: copy.moved !== moved && copy.moved.byteLength,
  decoded: new TextDecoder().decode(view),
};
"#
            ),
            serde_json::json!({
                "bufferIndependent": true,
                "bytes": [1, 2],
                "date": 5,
                "pattern": "/a/g",
                "map": [[1, 2]],
                "movedDetached": true,
                "movedCopy": 2,
                "decoded": "ok",
            })
        );
    }

    /// What a value is decides how it is cloned, not its prototype chain or
    /// constructors the value controls.
    #[test]
    fn structured_clone_follows_intrinsic_types_and_final_transfer_contents() {
        assert_eq!(
            evaluate(
                r#"
const fakeDate = structuredClone(Object.create(Date.prototype));
const bareMap = new Map([[1, 2]]);
Object.setPrototypeOf(bareMap, null);
const mapCopy = structuredClone(bareMap);
const victim = new ArrayBuffer(8);
const source = new ArrayBuffer(2);
source.constructor = { [Symbol.species]: function () { return victim; } };
const bufferCopy = structuredClone(source);
const moved = new Uint8Array([1]).buffer;
const written = structuredClone(
  { moved, get update() { new Uint8Array(moved)[0] = 2; return true; } },
  { transfer: [moved] }
);
const bareBuffer = new Uint8Array([7]).buffer;
Object.setPrototypeOf(bareBuffer, null);
const bareBufferCopy = structuredClone(bareBuffer, { transfer: [bareBuffer] });
const error = new DOMException("busy", "InvalidStateError");
const errorCopy = structuredClone(error);
return {
  fakeDatePrototype: Object.getPrototypeOf(fakeDate) === Object.prototype,
  bareMap: mapCopy instanceof Map && mapCopy.get(1),
  bareBufferTransferred: new Uint8Array(bareBufferCopy)[0],
  bufferIndependent: bufferCopy !== victim && bufferCopy.byteLength,
  transferredFinalByte: new Uint8Array(written.moved)[0],
  movedDetached: moved.detached,
  domException: errorCopy instanceof DOMException && `${errorCopy.name}: ${errorCopy.message}`,
};
"#
            ),
            serde_json::json!({
                "fakeDatePrototype": true,
                "bareMap": 2,
                "bareBufferTransferred": 7,
                "bufferIndependent": 2,
                "transferredFinalByte": 2,
                "movedDetached": true,
                "domException": "InvalidStateError: busy",
            })
        );
    }

    #[test]
    fn structured_clone_snapshots_collections_and_reads_own_error_fields() {
        assert_eq!(
            evaluate(
                r#"
const map = new Map();
map.set("first", { get value() { map.clear(); return 1; } });
map.set("second", 2);
const mapCopy = structuredClone(map);
class Inherited extends Error {}
Inherited.prototype.cause = () => "not cloneable";
const inherited = structuredClone(new Inherited("kept"));
let ran = false;
const accessor = new Error("quiet");
Object.defineProperty(accessor, "cause", { get() { ran = true; return 1; } });
const accessorCopy = structuredClone(accessor);
const caused = structuredClone(new Error("outer", { cause: { code: 7 } }));
return {
  mapKeys: [...mapCopy.keys()],
  inheritedMessage: inherited.message,
  inheritedCause: Object.hasOwn(inherited, "cause"),
  accessorRan: ran,
  accessorCause: Object.hasOwn(accessorCopy, "cause"),
  cause: caused.cause,
};
"#
            ),
            serde_json::json!({
                "mapKeys": ["first", "second"],
                "inheritedMessage": "kept",
                "inheritedCause": false,
                "accessorRan": false,
                "accessorCause": false,
                "cause": {"code": 7},
            })
        );
    }

    #[test]
    fn structured_clone_keeps_resizable_buffers_and_skips_removed_keys() {
        assert_eq!(
            evaluate(
                r#"
const resizable = new ArrayBuffer(2, { maxByteLength: 4 });
const resizableCopy = structuredClone(resizable);
const growing = new ArrayBuffer(2, { maxByteLength: 4 });
const grown = structuredClone(
  { growing, get grow() { growing.resize(4); new Uint8Array(growing)[3] = 9; return true; } },
  { transfer: [growing] }
);
const proto = { b: () => "inherited" };
const shrinking = Object.create(proto);
Object.defineProperty(shrinking, "a", { enumerable: true, get() { delete this.b; return 1; } });
shrinking.b = 2;
const shrunk = structuredClone(shrinking);
const refusedPair = (pairs) => {
  try {
    new URLSearchParams(pairs);
    return null;
  } catch (error) {
    return error.name;
  }
};
return {
  resizable: resizableCopy.resizable && resizableCopy.maxByteLength,
  grownLength: grown.growing.byteLength,
  grownByte: new Uint8Array(grown.growing)[3],
  shrunkKeys: Object.keys(shrunk),
  stringPair: refusedPair(["ab"]),
  arrayLikePair: refusedPair([{ 0: "a", 1: "b", length: 2 }]),
};
"#
            ),
            serde_json::json!({
                "resizable": 4,
                "grownLength": 4,
                "grownByte": 9,
                "shrunkKeys": ["a"],
                "stringPair": "TypeError",
                "arrayLikePair": "TypeError",
            })
        );
    }

    #[test]
    fn structured_clone_refuses_uncloneable_values_and_transfers_buffers() {
        assert_eq!(
            evaluate(
                r#"
const refusal = (value, options) => {
  try {
    structuredClone(value, options);
    return null;
  } catch (error) {
    return `${error.name}:${error instanceof DOMException}`;
  }
};
const kept = new ArrayBuffer(4);
const failed = refusal({ fn() {} }, { transfer: [kept] });
const moved = new Uint8Array([7, 8]).buffer;
const copy = structuredClone({ bytes: new Uint8Array(moved) }, { transfer: [moved] });
return {
  function: refusal(() => {}),
  symbol: refusal(Symbol("s")),
  promise: refusal(Promise.resolve()),
  weakMap: refusal(new WeakMap()),
  proxy: refusal(new Proxy({ x: 1 }, {})),
  proxiedArray: refusal(new Proxy([1], {})),
  generator: refusal((function* () { yield 1; })()),
  iterator: refusal(new Map([[1, 2]]).entries()),
  shared: refusal(new SharedArrayBuffer(4)),
  duplicate: refusal(null, { transfer: [moved, moved] }),
  failed,
  keptAfterFailure: kept.detached,
  movedDetached: moved.detached,
  movedBytes: Array.from(copy.bytes),
};
"#
            ),
            serde_json::json!({
                "function": "DataCloneError:true",
                "symbol": "DataCloneError:true",
                "promise": "DataCloneError:true",
                "weakMap": "DataCloneError:true",
                "proxy": "DataCloneError:true",
                "proxiedArray": "DataCloneError:true",
                "generator": "DataCloneError:true",
                "iterator": "DataCloneError:true",
                "shared": "DataCloneError:true",
                "duplicate": "DataCloneError:true",
                "failed": "DataCloneError:true",
                "keptAfterFailure": false,
                "movedDetached": true,
                "movedBytes": [7, 8],
            })
        );
    }

    #[test]
    fn url_parses_resolves_and_reports_components() {
        assert_eq!(
            evaluate(
                r#"
const page = new URL("../items?page=2&sort=name#top", "https://user:pw@example.com:8443/api/v1/list");
const invalid = (() => {
  try {
    new URL("not a url");
    return null;
  } catch (error) {
    return error.name;
  }
})();
return {
  href: page.href,
  origin: page.origin,
  protocol: page.protocol,
  username: page.username,
  password: page.password,
  host: page.host,
  hostname: page.hostname,
  port: page.port,
  pathname: page.pathname,
  search: page.search,
  hash: page.hash,
  page: page.searchParams.get("page"),
  json: JSON.stringify({ link: page }),
  invalid,
  canParse: [URL.canParse("https://a.example"), URL.canParse("relative"), URL.canParse("relative", "https://a.example")],
  parsed: URL.parse("nope"),
  defaultPort: new URL("https://example.com:443/").port,
};
"#
            ),
            serde_json::json!({
                "href": "https://user:pw@example.com:8443/api/items?page=2&sort=name#top",
                "origin": "https://example.com:8443",
                "protocol": "https:",
                "username": "user",
                "password": "pw",
                "host": "example.com:8443",
                "hostname": "example.com",
                "port": "8443",
                "pathname": "/api/items",
                "search": "?page=2&sort=name",
                "hash": "#top",
                "page": "2",
                "json": r#"{"link":"https://user:pw@example.com:8443/api/items?page=2&sort=name#top"}"#,
                "invalid": "TypeError",
                "canParse": [true, false, true],
                "parsed": null,
                "defaultPort": "",
            })
        );
    }

    #[test]
    fn url_setters_and_search_params_stay_linked() {
        assert_eq!(
            evaluate(
                r#"
const url = new URL("https://example.com/path?a=1&b=2");
url.searchParams.append("c", "x y");
const afterAppend = url.href;
url.search = "?z=9";
const fromSearch = url.searchParams.get("z");
url.searchParams.delete("z");
const afterDelete = url.href;
url.pathname = "/other path";
url.port = "8080";
url.hash = "frag";
url.protocol = "not a scheme";
url.hostname = "example.org";
return { afterAppend, fromSearch, afterDelete, final: url.href };
"#
            ),
            serde_json::json!({
                "afterAppend": "https://example.com/path?a=1&b=2&c=x+y",
                "fromSearch": "9",
                "afterDelete": "https://example.com/path",
                "final": "https://example.org:8080/other%20path#frag",
            })
        );
    }

    #[test]
    fn url_search_params_follow_form_encoding() {
        assert_eq!(
            evaluate(
                r#"
const parsed = new URLSearchParams("?a=1&b=x+y&c=%E2%9C%93&d=%zz&a=2&e");
const fromRecord = new URLSearchParams({ q: "café & co", n: 3 });
const fromPairs = new URLSearchParams([["b", "2"], ["a", "1"], ["b", "1"]]);
fromPairs.sort();
const edited = new URLSearchParams("a=1&a=2&b=3");
edited.set("a", "only");
edited.delete("b", "4");
const visited = [];
edited.forEach((value, name) => visited.push(`${name}=${value}`));
const badPair = (() => {
  try {
    new URLSearchParams([["only one"]]);
    return null;
  } catch (error) {
    return error.name;
  }
})();
return {
  all: parsed.getAll("a"),
  space: parsed.get("b"),
  decoded: parsed.get("c"),
  malformed: parsed.get("d"),
  empty: parsed.get("e"),
  missing: parsed.get("nope"),
  has: [parsed.has("a", "2"), parsed.has("a", "3")],
  size: parsed.size,
  record: fromRecord.toString(),
  sorted: [...fromPairs].map(([name, value]) => `${name}=${value}`),
  keys: [...fromPairs.keys()],
  edited: edited.toString(),
  visited,
  badPair,
};
"#
            ),
            serde_json::json!({
                "all": ["1", "2"],
                "space": "x y",
                "decoded": "✓",
                "malformed": "%zz",
                "empty": "",
                "missing": null,
                "has": [true, false],
                "size": 6,
                "record": "q=caf%C3%A9+%26+co&n=3",
                "sorted": ["a=1", "b=2", "b=1"],
                "keys": ["a", "b", "b"],
                "edited": "a=only&b=3",
                "visited": ["a=only", "b=3"],
                "badPair": "TypeError",
            })
        );
    }

    /// The Code Mode reference lists the globals a program can rely on and the
    /// common Node.js and browser globals it cannot. Keep that list and this
    /// one in step.
    #[test]
    fn runtime_globals_match_the_documented_surface() {
        let result = execute_with(
            r#"
return {
  present: {
    connectors: typeof connectors,
    execution: typeof execution,
    atob: typeof atob,
    btoa: typeof btoa,
    queueMicrotask: typeof queueMicrotask,
    performanceNow: typeof performance.now,
    fromBase64: typeof Uint8Array.fromBase64,
    toBase64: typeof Uint8Array.prototype.toBase64,
    DOMException: typeof DOMException,
    console: typeof console,
    consoleLog: typeof console.log,
    TextEncoder: typeof TextEncoder,
    TextDecoder: typeof TextDecoder,
    randomUUID: typeof crypto.randomUUID,
    getRandomValues: typeof crypto.getRandomValues,
    structuredClone: typeof structuredClone,
    URL: typeof URL,
    URLSearchParams: typeof URLSearchParams,
  },
  absent: {
    subtle: typeof crypto.subtle,
    Buffer: typeof Buffer,
    setTimeout: typeof setTimeout,
    setInterval: typeof setInterval,
    fetch: typeof fetch,
    require: typeof require,
    process: typeof process,
    Intl: typeof Intl,
  },
};
"#,
            &[],
            |_| unreachable!("program makes no connector calls"),
        )
        .expect("program executes");

        for (name, kind) in result["present"].as_object().expect("present globals") {
            assert_ne!(kind, "undefined", "{name} is documented as available");
        }
        for (name, kind) in result["absent"].as_object().expect("absent globals") {
            assert_eq!(kind, "undefined", "{name} is documented as absent");
        }
    }
}
