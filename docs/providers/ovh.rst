ovh
    * ``auth_entrypoint`` Specify the ovh entrypoint

    * ``auth_application_key`` Specify the application key

    * ``auth_application_secret`` Specify the application secret

    * ``auth_consumer_key`` Specify the consumer key

    * ``auth_client_id`` Specify the oauth2 client id of a service account (instead of the application key, secret and consumer key)

    * ``auth_client_secret`` Specify the oauth2 client secret of a service account


.. note::
   
   OVH Provider requires a token with full rights on /domain/*.
   It can be generated for your OVH account on the following URL:
   https://api.ovh.com/createToken/index.cgi?GET=/domain/*&PUT=/domain/*&POST=/domain/*&DELETE=/domain/*
   Alternatively, give the client ID and secret of an OVHcloud service account
   (OAuth2 client credentials, entrypoints ovh-eu, ovh-ca and ovh-us) whose IAM
   policy allows the domain zone actions, instead of the application key,
   application secret and consumer key.

