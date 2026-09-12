-- Keep policy identities and token balances while naming this action for
-- the side effects that determine quota selection.
ALTER TABLE rate_limit_policies
    DROP CONSTRAINT rate_limit_policies_action_check;

UPDATE rate_limit_policies
SET action = 'side_effecting_call'
WHERE action = 'high_risk_call';

ALTER TABLE rate_limit_policies
    ADD CONSTRAINT rate_limit_policies_action_check
    CHECK (action IN ('call', 'side_effecting_call', 'cost_bearing', 'discovery'));
