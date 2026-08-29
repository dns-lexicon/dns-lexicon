gransy
    * ``auth_username`` Specify username for authentication

    * ``auth_password`` Specify password for authentication

    * ``remote_api_definition`` Use the SOAP API definition served by subreg.cz instead of the bundled one


.. note::
   
   DNS manipulation provider for Gransy sites subreg.cz, regtons.com and regnames.eu.

   The SOAP API definition is bundled; if Gransy changes the API, ``--remote-api-definition`` uses the one served by subreg.cz instead, on every run, until the bundled copy is refreshed.
