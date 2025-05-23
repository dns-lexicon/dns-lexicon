==================
Technical workbook
==================

Provider conventions
====================

The conventions described in this section must be followed by any provider implementation.

Contract of a Lexicon record
----------------------------

A Lexicon record is the internal representation of a DNS entry fetched or pushed to a DNS provider API.
These records are JSON objects that **must** follows the given contract.

Required fields
~~~~~~~~~~~~~~~

-  **name** Clients should provide FQDN. Providers should handle both
   FQDN and relative names.
-  **ttl** Reasonable default is 6 hours since it’s supported by most
   services. Any service that does not support this must be explicitly
   mentioned somewhere.
-  **record** All provider/API records must be translated to the
   following format:

Example of a Lexicon record
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   {
       'id': string, // optional, provider specified unique id. Clients to treat this as opaque.
       'type': string, // upper case, valid record type. eg. A, CNAME, TXT
       'name': string, // lowercase, FQDN. eg. test.record.example.com
       'ttl': integer, // positive integer, in seconds. eg. 3600
       'content': string, //double quoted/escaped values should be unescaped. eg. "\"TXT content\"" should become "TXT content"
       'options': {
           'mx': { // MX options
               'priority': integer
           }
       }
   }

DNS operations
--------------

A Lexicon provider will have to make operations against a DNS provider API.
Here are the 5 possible operations, and the behavior each operation **must** follow.

authenticate
~~~~~~~~~~~~

- **Normal Behavior** Execute all required operations to authenticate against the provider API, then
  retrieves the identifier of the domain and assign it to the ``self.domain_id`` property of the
  ``Provider`` instance.
- **Authentication failure** In case of authentication failure, the method **must** raise a
  ``lexicon.exceptions.AuthenticationError`` exception and break the flow.

create_record
~~~~~~~~~~~~~

-  **Normal Behavior** Create a new DNS record. Return a boolean
   ``True`` if successful.
-  **If Record Already Exists** Do nothing. **DO NOT** throw exception.
-  **TTL** If not specified or set to ``0``, use reasonable default.
-  **Record Sets** If service supports record sets, create new record
   set or append value to existing record set as required.

list_record
~~~~~~~~~~~

-  **Normal Behaviour** List all records. If filters are provided, send
   to the API if possible, else apply filter locally. Return value
   should be a list of records.
-  **Record Sets** Ungroup record sets into individual records. Eg: If a
   record set contains 3 values, provider ungroup them into 3 different
   records.
-  **Linked Records** For services that support some form of linked
   record, do not resolve, treat as CNAME.

update_record
~~~~~~~~~~~~~

-  **Normal Behaviour** Update a record. Record to be updated can be
   specified by providing id OR name, type and content. Return a boolean
   ``True`` if successful.
-  **Record Sets** If matched record is part of a record set, only
   update the record that matches. Update the record set so that records
   other than the matched one are unmodified.
-  **TTL**

   -  If not specified, do not modify ttl.
   -  If set to ``0``, reset to reasonable default.

-  **No Match** Throw exception?

delete_record
~~~~~~~~~~~~~

-  **Normal Behaviour** Remove a record. Record to be deleted can be
   specified by providing id OR name, type and content. Return a boolean
   ``True`` if successful.
-  **Record sets** Remove only the record that matches all the filters.

   -  If content is not specified, remove the record set.
   -  If length of record set becomes 0 after removing record, remove
      the record set.
   -  Otherwise, remove only the value that matches and leave other
      records as-is.

-  **No Match** Do nothing. **DO NOT** throw exception

Code documentation
==================

This section describes the public API of Lexicon code (classes, methods, functions) useful
to implement a new provider, or to interface Lexicon as a library to another project.

Module `lexicon.client`
-----------------------

.. automodule:: lexicon.client
   :members:

Module `lexicon.interfaces`
---------------------------

.. automodule:: lexicon.interfaces
   :members:

Module `lexicon.config`
-----------------------

.. automodule:: lexicon.config
   :members:

Module `lexicon.exceptions`
---------------------------

.. automodule:: lexicon.exceptions
   :members:
