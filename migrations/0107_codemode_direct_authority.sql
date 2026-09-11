ALTER TABLE codemode_skill_script_grants
    DROP CONSTRAINT codemode_skill_script_grants_execution_profile_check;

ALTER TABLE codemode_skill_script_grants
    ADD CONSTRAINT codemode_skill_script_grants_execution_profile_check
    CHECK (execution_profile = 'direct') NOT VALID;
