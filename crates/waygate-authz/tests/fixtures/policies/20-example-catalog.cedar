
@id("example-catalog-product-resources")
@layer("service-grants")
@description("Authenticated Example catalog users may list resources and read the product_v1 design and rendering guides.")
@tags("example-catalog, resources, product-guidance")
permit (
    principal,
    action,
    resource
) when {
    (
        action == Action::"ListResources"
        && resource is Server
        && resource.name == "example-catalog"
    )
    ||
    (
        action == Action::"ReadResource"
        && resource is Resource
        && resource.server == "example-catalog"
        && (
            resource.uri == "example-catalog://example-guides/design-v1"
            || resource.uri == "example-catalog://example-guides/render-v1"
        )
    )
};
