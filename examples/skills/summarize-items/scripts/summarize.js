const items = execution.input.items;
const counts = new Map();
for (const item of items) {
  counts.set(item.status, (counts.get(item.status) || 0) + 1);
}
return { total: items.length, by_status: Object.fromEntries(counts) };
