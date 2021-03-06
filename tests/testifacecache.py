#!/usr/bin/env python
from basetest import BaseTest
import sys, tempfile, os, time
import unittest
import data

sys.path.insert(0, '..')
from zeroinstall.injector import model, gpg, trust
from zeroinstall.injector.namespaces import config_site
from zeroinstall.injector.iface_cache import PendingFeed
from zeroinstall.support import basedir

class TestIfaceCache(BaseTest):
	def testList(self):
		iface_cache = self.config.iface_cache
		self.assertEquals([], iface_cache.list_all_interfaces())
		iface_dir = basedir.save_cache_path(config_site, 'interfaces')
		file(os.path.join(iface_dir, 'http%3a%2f%2ffoo'), 'w').close()
		self.assertEquals(['http://foo'],
				iface_cache.list_all_interfaces())
		# TODO: test overrides

	def testCheckSigned(self):
		iface_cache = self.config.iface_cache
		trust.trust_db.trust_key(
			'92429807C9853C0744A68B9AAE07828059A53CC1')
		feed_url = 'http://foo'
		src = tempfile.TemporaryFile()

		# Unsigned
		src.write("hello")
		src.flush()
		src.seek(0)
		try:
			PendingFeed(feed_url, src)
			assert 0
		except model.SafeException:
			pass

		stream = tempfile.TemporaryFile()
		stream.write(data.thomas_key)
		stream.seek(0)

		gpg.import_key(stream)

		# Signed
		src.seek(0)
		src.write(data.foo_signed_xml)
		src.flush()
		src.seek(0)

		pending = PendingFeed(feed_url, src)
		assert iface_cache.update_feed_if_trusted(feed_url, pending.sigs, pending.new_xml)

		self.assertEquals(['http://foo'],
				iface_cache.list_all_interfaces())

		feed = iface_cache.get_feed(feed_url)

		self.assertEquals(1154850229, feed.last_modified)

	def testXMLupdate(self):
		iface_cache = self.config.iface_cache
		trust.trust_db.trust_key(
			'92429807C9853C0744A68B9AAE07828059A53CC1')
		stream = tempfile.TemporaryFile()
		stream.write(data.thomas_key)
		stream.seek(0)
		gpg.import_key(stream)

		iface = iface_cache.get_interface('http://foo')
		src = tempfile.TemporaryFile()
		src.write(data.foo_signed_xml)
		src.seek(0)
		pending = PendingFeed(iface.uri, src)
		assert iface_cache.update_feed_if_trusted(iface.uri, pending.sigs, pending.new_xml)

		iface_cache.__init__()
		feed = iface_cache.get_feed('http://foo')
		assert feed.last_modified == 1154850229

		# mtimes are unreliable because copying often changes them -
		# check that we extract the time from the signature when upgrading
		upstream_dir = basedir.save_cache_path(config_site, 'interfaces')
		cached = os.path.join(upstream_dir, model.escape(feed.url))
		os.utime(cached, None)

		iface_cache.__init__()
		feed = iface_cache.get_feed('http://foo')
		assert feed.last_modified > 1154850229

		src = tempfile.TemporaryFile()
		src.write(data.new_foo_signed_xml)
		src.seek(0)

		pending = PendingFeed(feed.url, src)
		assert iface_cache.update_feed_if_trusted(feed.url, pending.sigs, pending.new_xml)

		# Can't 'update' to an older copy
		src = tempfile.TemporaryFile()
		src.write(data.foo_signed_xml)
		src.seek(0)
		try:
			pending = PendingFeed(feed.url, src)
			assert iface_cache.update_feed_if_trusted(feed.url, pending.sigs, pending.new_xml)

			assert 0
		except model.SafeException:
			pass

	def testTimes(self):
		iface_cache = self.config.iface_cache
		stream = tempfile.TemporaryFile()
		stream.write(data.thomas_key)
		stream.seek(0)
		gpg.import_key(stream)

		upstream_dir = basedir.save_cache_path(config_site, 'interfaces')
		cached = os.path.join(upstream_dir, model.escape('http://foo'))

		stream = file(cached, 'w')
		stream.write(data.foo_signed_xml)
		stream.close()

		signed = iface_cache._get_signature_date('http://foo')
		assert signed == None

		trust.trust_db.trust_key(
			'92429807C9853C0744A68B9AAE07828059A53CC1')

		signed = iface_cache._get_signature_date('http://foo')
		assert signed == 1154850229

		stream = file(cached, 'w+')
		stream.seek(0)
		stream.write('Hello')
		stream.close()

		# When the signature is invalid, we just return None.
		# This is because versions < 0.22 used to corrupt the signatue
		# by adding an attribute to the XML
		signed = iface_cache._get_signature_date('http://foo')
		assert signed == None

	def testCheckAttempt(self):
		iface_cache = self.config.iface_cache
		self.assertEquals(None, iface_cache.get_last_check_attempt("http://foo/bar.xml"))

		start_time = time.time() - 5	# Seems to be some odd rounding here
		iface_cache.mark_as_checking("http://foo/bar.xml")
		last_check = iface_cache.get_last_check_attempt("http://foo/bar.xml")

		assert last_check is not None
		assert last_check >= start_time, (last_check, start_time)

		self.assertEquals(None, iface_cache.get_last_check_attempt("http://foo/bar2.xml"))

	def testIsStale(self):
		iface_cache = self.config.iface_cache
		feed = self.import_feed('http://localhost:8000/Hello', 'Hello')
		assert iface_cache.is_stale(feed, 1) == True
		assert iface_cache.is_stale(feed, time.time() + 1) == False
		iface_cache.mark_as_checking(feed.url)
		assert iface_cache.is_stale(feed, 1) == False

if __name__ == '__main__':
	unittest.main()
