azure

* `auth_client_id` specify the client ID (aka application ID) of the App registration
* `auth_client_secret` specify the client secret of the App registration
* `auth_tenant_id` specify the tenant ID (aka directory ID) of the App registration
* `auth_subscription_id` specify the subscription ID attached to the resource group
* `resource_group` specify the resource group hosting the DNS zone to edit

```{note}
The Azure provider orchestrates the DNS zones hosted in a resource group for a subscription
in Microsoft Azure Cloud. To authenticate, an App registration must be created in an Azure
Active Directory. This App registration must be granted Admin for API permissions to
Domain.ReadWrite.All" to this Active Directory, and must have a usable Client secret.

```
