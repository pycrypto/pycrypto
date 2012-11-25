# -*- coding: utf-8 -*-

"""

Python library to work with CouchDB and to save python objects, handles conflict resolution on class attribute level.

This source code is licensed under the GNU General Public License,
Version 3. http://www.gnu.org/licenses/gpl-3.0.en.html

Copyright (C)

Erik de Jonge <erik@a8.nl>
Actve8 BV
Rotterdam
www.a8.nl

Important the query server needs python

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

"""

import time
import couchdb
import urllib2
import urlparse
import socket
import uuid
import inflection
import base64
import pickle
import logging

from couchdb.design import ViewDefinition

def error(msg):
    """
    logging error
    @param msg: the error message
    @type msg: string
    """

    logging.error(msg)


def report(msg):
    """
    info log

    @param msg: the error message
    @type msg: string
    """

    logging.warning(msg)


def object_to_pickled_base64(obj):
    """

    @param obj:
    @type obj:
    @return:
    @rtype:
    """
    return base64.b64encode(pickle.dumps(obj))


def pickled_base64_to_object(p64):
    """
    base64 pickled string to python object

    @param p64:b64 encoded object
    @type p64:string
    @return:a python object
    @rtype:object
    """

    return pickle.loads(base64.b64decode(str(p64)))


#noinspection PyUnusedLocal
def server_available(url, timeout=1):
    """
    try to make a connection to a server

    @param url:the url to check
    @type url:string
    @param timeout:number of seconds to wait
    @type timeout:float
    @return:is server up
    @rtype:bool
    """

    try:
        urllib2.urlopen(url, timeout=timeout)
        return True
    except urllib2.URLError, ex:
        report(url + " is down\n" + str(ex))
    except socket.timeout, ex:
        report(url + " is down\n" + str(ex))
    return False


def get_server(servers):
    """
    try all couch servers and get the first one which is up

    @param servers:list of servers to try
    @type servers:list
    @return:the couchdb server
    @rtype:couchdb.Server
    """

    for server in servers:
        if server_available(server):
            return couchdb.Server(server), server
    raise Exception("No servers available")


def _replicate(database, servers):
    """
    replicate between all servers, replication is done both ways

    @param database:database name
    @type database:string
    @param servers:list of servers
    @type servers:list
    @return:replication succesfull
    @rtype:bool
    """

    if not len(servers) > 1:
        return
    no_servers = False
    for server in servers:
        if not server_available(server, 0.5):
            no_servers = True
    if no_servers:
        for server in servers:
            if not server_available(server, 5):
                return False
    couch, couch_ip = get_server(servers)
    for server1 in servers:
        for server2 in servers:
            if server1 != server2:
                server1db = urlparse.urljoin(server1, database)
                server2db = urlparse.urljoin(server2, database)
                report(server1db + " --> " + server2db)
                couch.replicate(server1db, server2db)
    return True


def replicate(database, servers):
    """
    replicate between all servers, replication is done both ways

    @param database:database name
    @type database:string
    @param servers:list of servers
    @type servers:list
    @return:replication succesfull
    @rtype:bool
    """

    return _replicate(database, servers)


class DBNotFound(Exception):
    """
    error thrown if db not found
    """
    pass


def _get_db(name, servers):
    """
    get a database from a couch server
    @param name:name of server
    @type name:string
    @param servers:list of server ips
    @type servers:list
    @return: the coucdhb db
    @rtype: couchdb.client.Database
    """

    couch, server_ip = get_server(servers)
    if name in couch:
        dbase = couch[name]
        return dbase, server_ip
    raise DBNotFound(str(couch) + "database " + name + " not found")


def get_guid():
    """
    generate a unique guid

    @return: guid
    @rtype: string
    """

    return uuid.uuid4().hex


class CouchNamedCluster(object):
    """
        object passed to the CouchDBServer class, contains name and a list of couchdb servers
    """

    def __init__(self, dbname, servers):
        """
        @param dbname: name of dbase
        @type dbname: string
        @param servers: list of server ips
        @type servers: list
        """
        self._dbname = dbname
        self._servers = servers

    def get_name(self):
        """
        get the name of the database

        @return: name of db
        @rtype: string
        """

        return self._dbname

    def get_servers(self):
        """
        returns a list with couchdb servers, these are automatically replicated
        @return: list of servers
        @rtype: list
        """

        return self._servers


class CouchDBServer(object):
    """ CouchDB functionality wrapped in a class """

    _dbase = None
    _replicate_change = False

    def __init__(self, db_named_cluster=None, replicate_change=True):
        """
        @param db_named_cluster: The name of the database and the ip-addresses of the cluster
        @type db_named_cluster: CouchNamedCluster
        @param replicate_change: replicate the changes
        @type replicate_change: bool
        """

        self._replicate_change = replicate_change

        if not db_named_cluster:
            return

        self._db_named_cluster = db_named_cluster

        self._dbase, server_ip = _get_db(self._db_named_cluster.get_name(), self._db_named_cluster.get_servers())

        if not self._dbase:
            raise Exception("database does not exist")

    def create(self, db_named_cluster):
        """
        create all the database on the cluster

        @param db_named_cluster: The name of the database and the ip-addresses of the cluster
        @type db_named_cluster: CouchNamedCluster
        @return: succes
        @rtype: bool
        """
        for server in db_named_cluster.get_servers():
            if not db_named_cluster.get_name() in couchdb.Server(server):
                couchdb.Server(server).create(db_named_cluster.get_name())
        self._db_named_cluster = db_named_cluster
        self._dbase, server_ip = _get_db(self._db_named_cluster.get_name(), self._db_named_cluster.get_servers())
        if not self._dbase:
            raise Exception("database does not exist")
        return True

    def ensure_dbs_on_servers(self):
        """ make sure the db is on all our couchdb servers """

        for server in self._db_named_cluster.get_servers():
            couch = couchdb.Server(server)
            if self._db_named_cluster.get_name() not in couch:
                couch.create(self._db_named_cluster.get_name())
        self.replicate_changes()

    def compact_database(self):
        """ remove old revisions, keep database small """

        self._dbase.compact()

    def get_db(self):
        """
        get database
        @return: the coucdhb db
        @rtype: couchdb.Database
        """

        return self._dbase

    def changes(self, since=0):
        """
        ask couch for the list of changes compared to 'since'

        @param since: the sequence number of couchdb
        @type since: int
        @return: changes and docs
        @rtype: dict
        """
        return self.get_db().changes(
            since=since,
            feed="normal",
            style="all_docs",
            limit=100,
            descending=1,
            include_docs=1,
        )

    def last_revision(self, _id, since):
        """
        determine the latsest sequence in couch

        @param _id: last revision
        @type _id: string
        @param since: since
        @type since: int
        @return: sequence and revision
        @rtype: tuple
        """

        thechanges = self.changes(since)
        for change in thechanges["results"]:
            if _id == change["id"]:
                for rev in change["changes"]:
                    return change["seq"], rev["rev"]
        return since, None


    def add_document(self, document, doc_id=None):
        """
        add a document to couch, make up a guid if not given

        @param document: the document
        @type document: dict
        @param doc_id: the id of the doc
        @type doc_id: string
        @return: id and revision
        @rtype: tuple
        """

        if not self._dbase:
            raise Exception("database not set")

        if type(document) != type(dict()):
            raise Exception("documents should be of type dictionary")

        if not doc_id:
            if "_id" in document:
                doc_id = unicode(document["_id"])
            else:
                doc_id = get_guid()

        if self._replicate_change:
            replicate(self._db_named_cluster.get_name(), self._db_named_cluster.get_servers())

        document["_id"] = doc_id
        doc_id, doc_rev = self._dbase.save(document)

        if self._replicate_change:
            replicate(self._db_named_cluster.get_name(), self._db_named_cluster.get_servers())

        return doc_id, doc_rev

    def get_document(self, doc_id):
        """
        get doc from couchdb

        @param doc_id: id of the document
        @type doc_id: string
        @return: document
        @rtype: dict
        """

        if not self._dbase:
            raise Exception("database not set")

        return self._dbase.get(doc_id)


    def delete_document(self, doc_id):
        """
        delete

        @param doc_id: the id of the doc
        @type doc_id: string
        """

        if not self._dbase:
            raise Exception("database not set")

        self._dbase.delete(self.get_document(doc_id))


    def get_all_document_ids(self):
        """
        get the whole database
        @return: list of doc ids
        @rtype: list
        """

        ids = []
        for i in self._dbase:
            ids.append(i)
        return ids

    def replicate_changes(self):
        """
        replicate couchdb instances

        @return:
        @rtype:
        """

        replicate(self._db_named_cluster.get_name(), self._db_named_cluster.get_servers())

    def set_views_designdocuments(self, couch_views):
        """
        Implementation, add a map-reduce class, will be transformed to python sourcelevel code in couch

        @param couch_views: list of couchdb view classes
        @type couch_views: list
        """

        couchdb.design.ViewDefinition.sync_many(self._dbase, couch_views)

    def run_view_as_dictlist(self, view, key=None):
        """
        return list of dicts for this view

        @param view: url of the view
        @type view: string
        @param key: key in the result
        @type key: string
        @return: list of dicts
        @rtype: list
        """

        return self._view_as_dictlist(view, key)

    def _view_as_dictlist(self, view, key=None, group=False):
        """
        return list of dicts for this view (implementation)

        @param view: url of the view
        @type view: string
        @param key: key in the result
        @type key: string
        @param group: group data
        @type group: bool
        @return: list of data
        @rtype: list
        """

        rows = []
        if group:
            result = self._dbase.view(view, group=True)
        else:
            result = self._dbase.view(view)

        if result.total_rows is None:
            # reduce result
            if result.rows:
                if not key:
                    raise Exception("reduce function needs a key")
                for row in result.rows:
                    if row["key"] == key:
                        return row["value"][1]
                else:
                    return 0
            else:
                return 0
        if key:
            for i in list(result[key]):
                doc = {
                    "id": i.id,
                    "key": i.key,
                    "value": i.value,
                }
                rows.append(doc)
        else:
            if not result.total_rows:
                if result.total_rows > 0:
                    for i in result.rows[0].values():
                        if i:
                            if type(i) == type(list()):
                                for j in i:
                                    rows.append(j)
                            else:
                                rows.append(i)
            else:
                for i in result.rows:
                    doc = {
                        "id": i.id,
                        "key": i.key,
                        "value": i.value,
                    }
                    rows.append(doc)
        return rows

    def add_views(self, classlist):
        """
        add a map-reduce class, will be transformed to python sourcelevel code in couch

        @param classlist: list of couchdb view classes
        @type classlist: list
        """

        self.set_views_designdocuments(classlist)

    def _run_view(self, methodname, key=None, scalar=False, value=True, group=False):
        """
        run a view in couch, if a doc should be unique use scalar
        @param methodname: name of the method to run
        @type methodname: string
        @param key: key of the data
        @type key: string
        @param scalar: expect one result
        @type scalar: bool
        @param value: return only the value
        @type value: bool
        @param group: group the data
        @type group: bool
        """
        methodname = inflection.underscore(methodname)
        if key:
            result = self._view_as_dictlist("_design/a8_couchdb_api/_view/" + methodname, key, group=group)
        else:
            result = self._view_as_dictlist("_design/a8_couchdb_api/_view/" + methodname, group=group)
        if scalar:
            if len(result) > 1:
                raise Exception("Found more then one value for: " + str(key))
            if len(result) == 1:
                result = result[0]
                if value:
                    return result["value"]
        return result

    def get_view_result_scalar(self, methodname, key=None, group=False):
        """
        run a view in couch, if a doc should be unique use scalar

        @param methodname: name of the method to run
        @type methodname: string
        @param key: key of the data
        @type key: string
        @param group: group the data
        @type group: bool
        @return: document
        @rtype: dict
        """
        return self._run_view(methodname, key, scalar=True, group=group)


    def get_view_results(self, methodname, key=None, group=False):
        """
        run a view in couch, if a doc should be unique use scalar

        @param methodname: name of the method to run
        @type methodname: string
        @param key: key of the data
        @type key: string
        @param group: group the data
        @type group: bool
        @return: list of document
        @rtype: list
        """
        return self._run_view(methodname, key, group=group)


#noinspection PyUnresolvedReferences
class CouchView(ViewDefinition):
    """
    A base class for couch views that handles the magic of instantiation.
    """

    def __init__(self):
        """
        Does some magic to map the subclass implementation into the format
        expected by ViewDefinition.
        """

        # module = sys.modules[self.__module__]

        design_name = "a8_couchdb_api"  # module.__name__.split(".")[-1]

        if hasattr(self.__class__, "map"):
            map_fun = self.__class__.map
        else:
            raise NotImplementedError("Couch views require a map() method.")

        if hasattr(self.__class__, "reduce"):
            reduce_fun = self.__class__.reduce
        else:
            reduce_fun = None

        super_args = (design_name, inflection.underscore(self.__class__.__name__), map_fun, reduce_fun, "python")

        super(CouchView, self).__init__(*super_args)


class GetObject(CouchView):
    """ Get all the cb_object docs, used by SaveObject """

    @staticmethod
    def map(object_dict):
        """ function called by couchdb

        @param object_dict:
        """

        if "doctype" in object_dict:
            if object_dict["doctype"] == "cb_object":
                yield (object_dict["_id"], object_dict)


class CountTypes(CouchView):
    """ Count the number of documents available, per type. """

    @staticmethod
    def map(object_dict):
        """ Emit the document type for each document.

        @param object_dict:
        """

        if "doctype" in object_dict:
            yield (object_dict["object_type"], 1)

    #noinspection PyUnusedLocal
    @staticmethod
    def reduce(keys, values, rereduce):
        """ Sum the values for each type.

        @param values:
        @param rereduce:
        @param keys:
        """

        return keys[0][0], sum(values)


class GetCryptoTask(CouchView):
    """ Optimization, get all the cb_object docs of CryptoTask type, used by SaveObject """

    @staticmethod
    def map(object_dict):
        """ emit docs

        @param object_dict:
        """

        if "doctype" in object_dict:
            if object_dict["doctype"] == "cb_object":
                if object_dict["object_type"] == "CryptoTask":
                    yield (object_dict["_id"], object_dict)


class ObjectSaveException(Exception):
    """ exception raised if the object cannot be saved """

    def __init__(self, exc, obj):
        objstr = str(obj.object_type) + ":" + str(obj.object_id)
        super(ObjectSaveException, self).__init__(exc + " -> " + objstr)


class ObjectDeleteException(Exception):
    """ exception raised if the object cannot be deleted """

    def __init__(self, exc, obj):
        objstr = str(obj.object_type) + ":" + str(obj.object_id)
        super(ObjectDeleteException, self).__init__(exc + " -> " + objstr)


class ObjectLoadException(Exception):
    """ exception raised if the object cannot be loaded """

    def __init__(self, exc, obj):
        objstr = str(obj.object_type) + ":" + str(obj.object_id)
        super(ObjectLoadException, self).__init__(exc + " -> " + objstr)


class MemberAddedToObjectException(Exception):
    """ exception raised if a member has been added """

    def __init__(self, exc, obj):
        objstr = str(obj.object_type) + ":" + str(obj.object_id)
        super(MemberAddedToObjectException, self).__init__(exc + " -> " + objstr)

#noinspection PyUnusedLocal
class SaveObject(object):
    """ Base class for saving python objects """

    object_id = None
    object_type = None
    comment = None
    seq = 0
    att_timestamps = None
    initial_value = {}

    def update_timestamp(self, attribute):
        """
        update a timestamp for a member attribute

        @param attribute: attribute to stamp
        @type attribute: string
        """

        self.att_timestamps[attribute] = time.time()

    def add_property(self, name):
        """
        generate a property with a timestamp entry

        @param name: name of the property
        @type name: string
        """

        self.initial_value[name] = getattr(self, name)
        setattr(self, "_" + name, getattr(self, name))
        setattr(self.__class__, name,
                property(lambda self: self.getattrc("_" + name), lambda self, value: self.setattrc("_" + name, value)))

    def getattrc(self, name):
        """
        get an attribute by name

        @param name: name of the prop
        @type name: string
        """

        if not hasattr(self, name):
            name = name.lstrip("_")
            if name in self.initial_value:
                return self.initial_value[name]
            return ""
        return getattr(self, name)

    def setattrc(self, name, value):
        """ set an attribute by name and update timestamp

        @param name:
        @param value:
        """

        if not hasattr(self, name):
            setattr(self, name, None)
        self.update_timestamp(name)
        setattr(self, name, value)

    def get_object_type(self):
        """ get the object type in a string format """

        object_type = str(repr(self))
        if "." in object_type:
            split = object_type.split(".")
            object_type = split[len(split) - 1]
        if " " in object_type:
            object_type = object_type.split(" ")[0]
            object_type = object_type.strip()
            return object_type
        else:
            return None

    def __init__(self, dbase=None, object_id=None, comment="a save object"):
        """
        @param dbase: database
        @type dbase: CouchDBServer
        @param object_id: id of object
        @type object_id: string
        @param comment: a comment
        @type comment: string
        """
        self.initial_value = {}
        self.att_timestamps = {}
        self.comment = comment
        self._dbase = dbase
        self.couchdb_document = {"doctype": "cb_object"}
        if object_id:
            self.object_id = object_id
        if not self.object_type:
            self.object_type = self.get_object_type()
        if not self.object_id:
            self.object_id = inflection.underscore(self.object_type) + "_" + str(uuid.uuid4().hex)
        for member in dir(self):
            if member.startswith("m_"):
                self.add_property(member)

    def count(self, dbase=None):
       """
       count the number of docs

       @param dbase: database
       @type dbase: CouchDBServer
       """

       if dbase:
           self._dbase = dbase
       if not self._dbase:
           raise ObjectLoadException("Database variable not set (_dbase)", self)
       self._dbase.add_views([CountTypes()])
       #noinspection PyTypeChecker
       number = self._dbase._run_view("CountTypes", key=self.object_type, group=True)
       return number

    def handleconflict(self, newest_doc, debug=False):
        """
        conflict resolution by comparing the timestamps of the member attributes

        @param newest_doc: document
        @type newest_doc: dict
        @param debug: debugging mode
        @type debug: bool
        """

        if debug:
            print
        for mymember in dir(self):
            if mymember.startswith("m_"):
                key = mymember
                mymember_timestamp = None
                newermember_timestamp = None
                if "_" + key in self.att_timestamps:
                    mymember_timestamp = self.att_timestamps["_" + key]
                if "_" + key in newest_doc["att_timestamps"]:
                    newermember_timestamp = newest_doc["att_timestamps"]["_" + key]
                if debug:
                    print "---------------------------------------------------------------------------"
                    print "key:", key
                    print "newer value:", newest_doc[key]
                    print "current value:", getattr(self, key)
                    print "newermember_timestamp:", newermember_timestamp
                    print "mymember_timestamp", mymember_timestamp
                    print "newermember_timestamp >= mymember_timestamp", newermember_timestamp >= mymember_timestamp
                    print "---------------------------------------------------------------------------"
                if mymember_timestamp:
                    if newermember_timestamp >= mymember_timestamp:
                        self.att_timestamps["_" + key] = newest_doc["att_timestamps"]["_" + key]
                        setattr(self, "_" + key, newest_doc[key])
                else:
                    self.att_timestamps["_" + key] = newest_doc["att_timestamps"]["_" + key]
                    setattr(self, "_" + key, newest_doc[key])


    def checkforconflicts(self, latest_rev, debug=False):
        """
        compare revision with latest revision in couch

        @param latest_rev: latest revision
        @param debug: string
        @param debug: debugging mode
        @type debug: bool
        """

        newest_doc = None
        if "_rev" in self.couchdb_document:
            if latest_rev != self.couchdb_document["_rev"]:
                self._dbase.add_views([GetObject()])
                newest_doc = self._dbase.get_view_result_scalar("GetObject", self.object_id)
        else:
            if latest_rev:
                self._dbase.add_views([GetObject()])
                newest_doc = self._dbase.get_view_result_scalar("GetObject", self.object_id)
                if len(newest_doc) == 0:
                    self.couchdb_document["_rev"] = latest_rev

        if newest_doc:
            self.handleconflict(newest_doc, debug)
            self.couchdb_document["_rev"] = latest_rev

    def save(self, object_id=None, dbase=None, debug=False, overwrite=True):
        """
        save the object, check for conflicsts and resolve them

        @param object_id: id of object
        @type object_id: string
        @param dbase: database
        @type dbase: CouchDBServer
        @param debug: debug?
        @type debug: bool
        @param overwrite: do not overwrite the data
        @type overwrite: bool
        @return: success
        @rtype: bool
        """
        if dbase:
            self._dbase = dbase
        if object_id:
            self.object_id = object_id
        if not self.object_id:
            raise ObjectSaveException("Object id not set (self.object_id)", self)
        if not self._dbase:
            raise ObjectSaveException("Database variable not set (_dbase)", self)

        if not overwrite:
            if self.count() > 0:
                return False

        (seq, latest_rev) = self._dbase.last_revision(self.object_id, self.seq)

        # print seq, latest_rev

        if seq - 1 != self.seq:
            self.checkforconflicts(latest_rev, debug)
        self.seq = seq

        for member in dir(self):
            if member.startswith("m_"):
                if member.endswith("_p64s"):
                    if type(getattr(self, member)) == type({}):
                        adict = getattr(self, member).copy()
                        for key in adict.keys():
                            adict[key] = object_to_pickled_base64(adict[key])
                        self.couchdb_document[member] = adict
                    else:
                        self.couchdb_document[member] = object_to_pickled_base64(getattr(self, member))
                else:
                    self.couchdb_document[member] = getattr(self, member)

                if member not in self.initial_value:
                    raise MemberAddedToObjectException("member field ["+str(member)+"] has been added dynamically during runtime, this is not allowed", self)
                if "_" + member not in self.att_timestamps:
                    self.update_timestamp("_" + member)

        self.couchdb_document["att_timestamps"] = self.att_timestamps
        self.couchdb_document["object_id"] = self.object_id
        self.couchdb_document["object_type"] = self.object_type
        self.couchdb_document["comment"] = self.comment
        self.couchdb_document["seq"] = self.seq
        self.couchdb_document["initial_value"] = self.initial_value

        try:
            if "_rev" in self.couchdb_document:
                if not self.couchdb_document["_rev"]:
                    del self.couchdb_document["_rev"]
            if latest_rev:
                self.couchdb_document["_rev"] = latest_rev
            self._dbase.add_document(self.couchdb_document, doc_id=self.object_id)
        except couchdb.ResourceConflict, ex:
            # does it still exist?
            error("Exception, save object: " + str(ex))
            object_dicts = self._dbase.get_view_results("GetObject", self.object_id)
            if len(object_dicts) == 0:
                return False
            import random

            time.sleep(random.randint(1, 3))
            self.seq = 0
            self.save(debug=debug)
        return True

    def exists(self, object_id=None, dbase=None):
        """
        does the record exist

        @param object_id: id of object
        @type object_id: string
        @param dbase: database
        @type dbase: CouchDBServer

        """

        if dbase:
            self._dbase = dbase
        if not self._dbase:
            raise ObjectLoadException("Database variable not set (_dbase)", self)
        if object_id:
            self.object_id = object_id
        if not self.object_id:
            raise ObjectLoadException("Object id not set (self.object_id)", self)
        self._dbase.add_views([GetObject()])
        object_dicts = self._dbase.get_view_results("GetObject", self.object_id)
        if len(object_dicts) == 0:
            return False
        return True

    def load(self, object_id=None, dbase=None):
        """
        load the object

        @param object_id: id of object
        @type object_id: string
        @param dbase: database
        @type dbase: CouchDBServer
        @return: success
        @rtype: bool
        """

        if dbase:
            self._dbase = dbase
        if not self._dbase:
            raise ObjectLoadException("Database variable not set (_dbase)", self)
        if object_id:
            self.object_id = object_id
        if not self.object_id:
            raise ObjectLoadException("Object id not set (self.object_id)", self)
        self._dbase.add_views([GetObject()])
        object_dicts = self._dbase.get_view_results("GetObject", self.object_id)
        if len(object_dicts) == 0:
            if "_rev" in self.couchdb_document:
                self.couchdb_document["_rev"] = self._dbase.last_revision(self.object_id, self.seq)
                return False
            else:
                return False
        object_dict = {}
        if len(object_dicts) == 1:
            object_dict = object_dicts[0]["value"]
        if len(object_dicts) > 1:
            raise ObjectLoadException("more then one object, should be impossible", self)
        att_timestamps = object_dict["att_timestamps"]
        del object_dict["att_timestamps"]
        self.object_id = object_dict["object_id"]
        del object_dict["object_id"]
        self.object_type = object_dict["object_type"]
        del object_dict["object_type"]
        self.comment = object_dict["comment"]
        del object_dict["comment"]
        self.seq = object_dict["seq"]
        del object_dict["seq"]
        self.initial_value = object_dict["initial_value"]
        del object_dict["initial_value"]
        self.set_from_dict(object_dict)
        self.att_timestamps = att_timestamps
        return True

    def collection(self, dbase=None):
        """
        return all the objects of this type as a list

        @param dbase: database
        @type dbase: CouchDBServer
        """

        if dbase:
            self._dbase = dbase
        if not self._dbase:
            raise ObjectLoadException("Database variable not set (_dbase)", self)
        if self.object_type == "CryptoTask":
            self._dbase.add_views([GetCryptoTask()])
            object_dicts = self._dbase.get_view_results("GetCryptoTask")
        else:
            self._dbase.add_views([GetObject()])
            object_dicts = self._dbase.get_view_results("GetObject")
        collection_list = []
        for object_dict in object_dicts:
            if object_dict["value"]["object_type"] == self.object_type:
                obj = self.__class__(dbase=self._dbase, object_id=object_dict["value"]["object_id"])
                obj.set_from_dict(object_dict["value"])
                collection_list.append(obj)
        return collection_list

    def set_from_dict(self, object_dict):
        """
        set the attributes from a dictionary

        @param object_dict:
        @type object_dict: dict
        """

        for key in object_dict:
            if key.endswith("_p64s"):
                if key == "m_aes_encrypted_rsa_private_key_p64s":
                    pass
                if type(object_dict[key]) == type({}):
                    adict = object_dict[key]
                    for key2 in adict.keys():
                        adict[key2] = pickled_base64_to_object(adict[key2])
                    setattr(self, key, adict)
                else:
                    object_dict[key] = pickled_base64_to_object(object_dict[key])
                    setattr(self, key, object_dict[key])
            else:
                setattr(self, key, object_dict[key])
            self.couchdb_document[key] = getattr(self, key)

    def reset(self):
        """ reset the object to the initial values """

        for i in dir(self):
            if i.startswith("m_"):
                if i in self.initial_value:
                    setattr(self, i, self.initial_value[i])

    #noinspection PyUnusedLocal
    def delete(self, dbase=None, raiseex=None):
        """
        delete the object

        @param dbase: database
        @type dbase: CouchDBServer
        @param raiseex: raise this exception
        @type raiseex: ResourceConflict
        """

        if dbase:
            self._dbase = dbase
        if not self._dbase:
            raise ObjectDeleteException("Database variable not set (_dbase)", self)
        if self.object_id:
            try:
                self._dbase.delete_document(self.object_id)
            except couchdb.ResourceConflict, ex:
                import random

                time.sleep(random.random() * 10)
                self.load()
                if raiseex:
                    raise ex
                self.delete(raiseex=ex)
        self.reset()

    def serialize_b64(self):
        """
        @return: base64 representation of object
        @rtype: string
        """
        sdict = self.__dict__
        del sdict["_dbase"]
        return object_to_pickled_base64(sdict)

    def deserialize_b64(self, b64_string):
        """
        @param b64_string: base64 representation of object
        @type b64_string: string
        """
        sdict = pickled_base64_to_object(b64_string)
        for key in sdict:
            self.__dict__[key] = sdict[key]
