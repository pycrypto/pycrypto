couchdb_api
===========

CouchDB library to save python objects, handles conflict resolution on class attribute level.


License
===========

<pre>
This source code is licensed under the GNU General Public License,
Version 3. http://www.gnu.org/licenses/gpl-3.0.en.html

Copyright (C)

Erik de Jonge <erik@a8.nl>
Actve8 BV
Rotterdam
www.a8.nl
</pre>

Features
===========

* Replication
* Automatic conflict resolution
* Thread safe
* Object database for standard python classes
* Support for complex python data (automatic pickeling)
* Wrapper around python couchb library
* Wrapper for views in python (thanks Mark Haasse -> http://markhaase.com/2012/06/23/couchdb-views-in-python/)


Dependency
===========

<pre>
http://pypi.python.org/pypi/inflection
</pre>
<pre>
Install http://pypi.python.org/pypi/CouchDB

And modify to be able to write map-reduce views in Python

$ locate local.ini
/etc/couchdb/local.ini

$ locate couchpy
/usr/bin/couchpy

$ sudo vi /etc/couchdb/local.ini

add

[query_servers]
python=/usr/bin/couchpy

restart couch
on linux
sudo /etc/init.d/couchdb stop
sudo /etc/init.d/couchdb start
</pre>

Workings
===========

If you inherit from the SaveObject class

```python
class Person(SaveObject):
    m_name = "John"
    m_age = 28
```

Then for all attributes starting with *m_* a property is created. This property keeps track of when each attribute was
last changed.

If you instantiate this class with the couchdbclass as the first parameter in the constructor and then call the save method.

```python
named_cluster = CouchNamedCluster("couchdb_api_test", all_servers)

# to create
server = CouchDBServer()
server.create(named_cluster)
# or shorthand if the database already exists
dbase = CouchDBServer("mytest")

person = Person(dbase)
person.save()
```

The object is stored in couch like this:

```json
{
    "_id": "person_d42f09f782ee45379018a7ee440a3547",
    "_rev": "1-7f59333831e9c62717dc0221587e4330",
    "comment": "a save object",
    "seq": 0,
    "initial_value": {
        "m_age": 28,
        "m_name": "John"
    },
    "att_timestamps": {
        "_m_age": 1351699518.1000521183,
        "_m_name": 1351699518.1000580788
    },
    "object_type": "Person",
    "doctype": "cb_object",
    "object_id": "person_d42f09f782ee45379018a7ee440a3547",
    "m_age": 28,
    "m_name": "John"
}
```
With this information the object can, in case of a conflic, determine which attribute is newer.

The object can later be restored from the database with the load command.

```python
dbase = CouchDBServer("mytest")
person = Person(dbase)
person.load()
```

And deleted with the delete command

```python
dbase = CouchDBServer("mytest")
person = Person(dbase, object_id="userid")
person.delete()
```

A collection of all the objects of a certain type can be retrieved with the collection method


```python
dbase = CouchDBServer("mytest")
person = Person(dbase)
for person in person.collection():
    print person.object_id, person.m_name
```

Attributes ending with *_p64s* will be pickeled and converted to base64. This is usesfull for encrypted data for example.

```python
class Person(SaveObject):
    m_name = "John"
    m_age = 28
    m_enc_rsa_priv_p64s = {}
```

