-- Positive: PL/pgSQL trigger body invokes a side-effect helper via SELECT
-- instead of PERFORM. The helper's return value is silently discarded.
-- Empirical anchor: dydx indexer realized-PnL handler.

CREATE OR REPLACE FUNCTION dydx_liquidation_handler()
RETURNS trigger AS $$
DECLARE
    fill_record record;
BEGIN
    -- Side-effect helper invoked without PERFORM. The realized-PnL row
    -- this returns is never read, so the side effect (insertion of a
    -- PnL row) is silently dropped.
    SELECT update_subaccount_balance(NEW.subaccount_id, NEW.fill_amount);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
