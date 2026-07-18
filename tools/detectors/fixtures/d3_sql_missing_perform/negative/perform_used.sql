-- Negative: same handler but uses PERFORM. Side-effect is guaranteed
-- because PERFORM discards the result intentionally and is the canonical
-- PL/pgSQL pattern for side-effect calls.

CREATE OR REPLACE FUNCTION dydx_liquidation_handler_ok()
RETURNS trigger AS $$
BEGIN
    PERFORM update_subaccount_balance(NEW.subaccount_id, NEW.fill_amount);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
