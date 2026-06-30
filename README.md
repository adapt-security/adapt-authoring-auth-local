# adapt-authoring-auth-local

Local (username/password) authentication for the Adapt authoring tool.

Implements `AbstractAuthModule` from [adapt-authoring-auth](../adapt-authoring-auth) — handling credential validation, password hashing and the login flow for users stored in the application's own database, as opposed to an external identity provider.
