@id("gateway-skills-example-origin")
@layer("service-grants")
@description("Authenticated users may list and read verified skills from the representative configured origin.")
@tags("skills, supply-chain, resources")
permit (
    principal,
    action in [
        Action::"ListSkills",
        Action::"FetchSkillResource",
        Action::"ReadSkill"
    ],
    resource is Resource
) when {
    resource.source_origin == "git+https://git.example/api/v1/team/skills"
};
