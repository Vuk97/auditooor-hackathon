-- Positive: caller invokes record_pnl_row(...) via SELECT without PERFORM.
-- record_pnl_row is declared earlier in this same file as a helper that
-- inserts into a pnl ledger table.

CREATE OR REPLACE FUNCTION record_pnl_row(
    subaccount_id uuid,
    realized numeric
) RETURNS uuid AS $BODY$
DECLARE
    new_id uuid;
BEGIN
    INSERT INTO realized_pnl (subaccount_id, realized)
    VALUES (subaccount_id, realized)
    RETURNING id INTO new_id;
    RETURN new_id;
END;
$BODY$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION dydx_deleveraging_handler()
RETURNS trigger AS $function$
BEGIN
    SELECT record_pnl_row(NEW.subaccount_id, NEW.realized);
    RETURN NEW;
END;
$function$ LANGUAGE plpgsql;
