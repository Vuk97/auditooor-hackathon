-- Negative cases:
--   1) SELECT ... INTO captures the result — not discarded.
--   2) A real query that uses a function call as a sub-expression with
--      FROM/WHERE — that's a column-expression, not a discarded
--      statement-level side-effect call.

CREATE OR REPLACE FUNCTION dydx_capture_ok()
RETURNS trigger AS $$
DECLARE
    new_id uuid;
    row_count int;
BEGIN
    -- INTO assignment: result is captured.
    SELECT record_pnl_row(NEW.subaccount_id, NEW.realized) INTO new_id;

    -- Real query: the function appears as a column-expression inside a
    -- FROM-bound SELECT. This is read-only at the statement level.
    SELECT count_open_positions(s.id) FROM subaccounts s WHERE s.active;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
