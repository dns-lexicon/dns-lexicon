ovh
    * ``auth_entrypoint`` Specify the ovh entrypoint

    * ``auth_application_key`` Specify the application key

    * ``auth_application_secret`` Specify the application secret

    * ``auth_consumer_key`` Specify the consumer key


.. note::
   
   OVH Provider requires a token with rights on the zone to manage,
   scoped to /domain/zone/example.com/* (replace example.com with your
   domain). It can be generated for your OVH account on the following URL:
   https://api.ovh.com/createToken/index.cgi?GET=/domain/zone/example.com/*&PUT=/domain/zone/example.com/*&POST=/domain/zone/example.com/*&DELETE=/domain/zone/example.com/*

