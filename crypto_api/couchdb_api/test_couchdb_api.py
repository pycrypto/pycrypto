# coding=utf-8
"""
    testprogram for couchdb
"""

import time
import threading
from __init__ import CouchDBServer, SaveObject, CouchNamedCluster


class Test(SaveObject):
    """
    saveable object
    """
    m_my_var = "m_my_var"
    m_my_var1 = "m_my_var1"


class TestP(SaveObject):
    """
    saveable object
    """
    m_my_var_p64s = "m_my_var"
    m_my_var1_p64s = {"hello":"m_my_var1"}


class Person(SaveObject):
    """
    saveable object
    """
    m_name = "John"
    m_age = 28


class MyThread(threading.Thread):
    """
        test thread
    """

    def __init__(self, dbase, object_id, cnt):
        self.object_id = object_id
        self.dbase = dbase
        self.cnt = str(cnt)
        threading.Thread.__init__(self)

    def run(self):
        """
            start a test
        """
        import random

        time.sleep(random.random() * 5)
        print "start: " + self.cnt
        test = Test(self.dbase)
        #noinspection PyUnresolvedReferences
        test.load(self.object_id)
        test.m_my_var = time.time()
        test.save()
        print "done: " + self.cnt + " -> " + str(test.m_my_var)


def threaded_test():
    """
        threaded test
    """
    named_cluster = CouchNamedCluster("couchdb_api_test", ["http://127.0.0.1:5984/"])
    dbase = CouchDBServer(named_cluster)
    testobj = Test(dbase, object_id="testset")

    threads = []
    testobj.save()

    for i in range(0, 20):
        mythread = MyThread(dbase, "testset", i)

        # time.sleep(0.1)

        mythread.start()
        threads.append(mythread)
    testobj.m_my_var = "dit is de nieuweste"
    testobj.save()

    print "waiting"
    for thread in threads:
        thread.join()


def simple_save(dname):
    """
        save an object to couch
    :param dname:
    @param dname:
    """
    dbase = CouchDBServer(dname, replicate_change=False)
    testobj = Test(dbase)
    testobj.m_my_var = "simple_save"
    testobj.m_my_var1 = "simple_save1"
    testobj.save()
    dbase.replicate_changes()
    print "end value is:", testobj.m_my_var


def delete_all_test_objects(dname):
    """
        delete all objects
    :param dname:
    @param dname:
    """
    dbase = CouchDBServer(dname, replicate_change=False)
    testobj = Test(dbase, object_id="testset")
    testpobj = TestP(dbase, object_id="testset")
    person = Person(dbase)
    #noinspection PyUnresolvedReferences
    for tst in testobj.collection():
        print tst
        tst.delete()
        print tst
    #noinspection PyUnresolvedReferences
    for tst in testpobj.collection():
        print tst
        tst.delete()
    #noinspection PyUnresolvedReferences
    for person in person.collection():
        print person.object_id, person.m_name
        person.delete()
    dbase.replicate_changes()


def load_wait_save(dname):
    """
        delete all objects form couch
    :param dname:
    @param dname:
    """
    dbase = CouchDBServer(dname)
    testobj = Test(dbase, object_id="testset")

    #noinspection PyUnresolvedReferences
    testobj.load()
    testobj.m_my_var = "load_wait_save"
    testobj.m_my_var1 = "load_wait_save1"
    raw_input("press enter")
    testobj.save(debug=True)


def save_person(dname):
    """
      save person object
    :param dname:
    @param dname:
    """
    dbase = CouchDBServer(dname)
    person = Person(dbase)
    person.save()


def collectiontest(named_cluster):
    """
    loop a collection
    :param named_cluster:
    @param named_cluster:
    """
    dbase = CouchDBServer(named_cluster)
    person = Person(dbase)
    test = Test(dbase)
    print "persons: ", person.count()
    print "test: ", test.count()
    print
    #noinspection PyUnresolvedReferences
    for person in person.collection():
        print person.object_id, person.m_name
    print
    #noinspection PyUnresolvedReferences
    for test in test.collection():
        print test.object_id


def delete_database(named_cluster):
    """
    delete a database
    :param named_cluster:
    @param named_cluster:
    """
    import couchdb

    print "deleting database"
    for server in named_cluster.get_servers():
        couchdb.Server(server).delete(named_cluster.get_name())


def serialize_person(named_cluster):
    """
    serialize an object
    :param named_cluster:
    @param named_cluster:
    """
    dbase = CouchDBServer(named_cluster)
    person = Person(dbase)
    person.m_age = 32
    person.m_naam = "arie"
    person.save()
    #noinspection PyUnresolvedReferences
    b64_string = person.serialize_b64()
    person2 = Person(dbase)
    #noinspection PyUnresolvedReferences
    person2.deserialize_b64(b64_string)
    print person2


def pickle_base64_test(named_cluster):
    """
    test the pickle base64 serialization
    :param named_cluster:
    @param named_cluster:
    """
    #delete_all_test_objects(named_cluster)
    dbase = CouchDBServer(named_cluster)
    testp = TestP(dbase, "testp")
    testp.m_my_var_p64s = "touch"
    testp.save()

    testp2 = TestP(dbase, "testp")
    #noinspection PyUnresolvedReferences
    testp2.load()

    print "done"

def main():
    """
        main function
    """
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-t", dest="test", help="""
                        1=simple_save
                        2=delete_all_test_objects
                        3=load_wait_save
                        4=save_person
                        5=collectiontest
                        6=delete couchdb_api_test db from all servers
                        """)
    args = parser.parse_args()

    all_servers = [
        "http://127.0.0.1:5984/",
        #"http://192.168.14.7:5984/",
        #"http://127.0.0.1:9000/",
        #"http://127.0.0.1:9001/",
        #"http://127.0.0.1:9002/"
    ]

    named_cluster = CouchNamedCluster("couchdb_api_test", all_servers)
    server = CouchDBServer()
    server.create(named_cluster)

    if args.test:
        testvalue = int(args.test)
    else:
        testvalue = 0

    print "currenttime:", time.time()

    if testvalue == 1:
        simple_save(named_cluster)
        simple_save(named_cluster)
        simple_save(named_cluster)
    elif testvalue == 2:
        delete_all_test_objects(named_cluster)
    elif testvalue == 3:
        load_wait_save(named_cluster)
    elif testvalue == 4:
        save_person(named_cluster)
    elif testvalue == 5:
        collectiontest(named_cluster)
    elif testvalue == 6:
        delete_database(named_cluster)
    elif testvalue == 7:
        serialize_person(named_cluster)
    elif testvalue == 8:
        pickle_base64_test(named_cluster)
    else:
        parser.print_help()
    import os

    print "done", os.popen("ps aux | grep test_couchdb_api.py").read()


if __name__ == "__main__":
    main()
