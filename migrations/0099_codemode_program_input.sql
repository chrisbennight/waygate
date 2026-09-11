-- Caller-supplied data a program reads instead of having the values edited
-- into its text. Bound durably at submission because a resumed or retried
-- attempt re-runs the same source from the top: without the original input the
-- replayed program would take a different path than the attempt it continues.
--
-- Deliberately separate from source_digest. That digest identifies the program
-- bytes and governs retention and admission, and it must stay stable across
-- input values so one retained program can serve many of them. Distinguishing
-- two starts that differ only by input is the start_dedupe_key's job.

ALTER TABLE codemode_executions
    ADD COLUMN program_input JSONB;
