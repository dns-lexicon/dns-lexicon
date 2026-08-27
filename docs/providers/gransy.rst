gransy
    * ``auth_username`` Specify username for authentication (SOAP API)

    * ``auth_password`` Specify password for authentication (SOAP API)

    * ``remote_api_definition`` Use the SOAP API definition served by subreg.cz instead of the bundled one

    * ``auth_token`` Specify Bearer token for authentication. When provided, the REST API is used instead of the SOAP API.


.. note::

   DNS manipulation provider for Gransy sites subreg.cz, regtons.com and regnames.eu.

   Authentication can be provided either as username/password (SOAP API at ``https://subreg.cz/wsdl``) or as a Bearer token (REST API at ``https://api.subreg.cz``). When ``auth_token`` is set, the REST API is used.

   The SOAP API definition is bundled; if Gransy changes the API, ``--remote-api-definition`` uses the one served by subreg.cz instead, on every run, until the bundled copy is refreshed.
