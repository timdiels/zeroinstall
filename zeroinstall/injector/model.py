"""In-memory representation of interfaces and other data structures.

The objects in this module are used to build a representation of an XML interface
file in memory.

@see: L{reader} constructs these data-structures
@see: U{http://0install.net/interface-spec.html} description of the domain model

@var defaults: Default values for the 'default' attribute for <environment> bindings of
well-known variables.
"""

# Copyright (C) 2009, Thomas Leonard
# See the README file for details, or visit http://0install.net.

from zeroinstall import _
import os, re, locale
from logging import info, debug, warn
from zeroinstall import SafeException, version
from zeroinstall.injector.namespaces import XMLNS_IFACE
from zeroinstall.injector import qdom
from zeroinstall.zerostore import unpack
from zeroinstall.support import tasks

# Element names for bindings in feed files
binding_names = frozenset(['environment', 'overlay'])

network_offline = 'off-line'
network_minimal = 'minimal'
network_full = 'full'
network_levels = (network_offline, network_minimal, network_full)

stability_levels = {}	# Name -> Stability

defaults = {
	'PATH': '/bin:/usr/bin',
	'XDG_CONFIG_DIRS': '/etc/xdg',
	'XDG_DATA_DIRS': '/usr/local/share:/usr/share',
}

class InvalidInterface(SafeException):
	"""Raised when parsing an invalid feed."""
	feed_url = None

	def __init__(self, message, ex = None):
		if ex:
			try:
				message += "\n\n(exact error: %s)" % ex
			except:
				# Some Python messages have type str but contain UTF-8 sequences.
				# (e.g. IOException). Adding these to a Unicode 'message' (e.g.
				# after gettext translation) will cause an error.
				import codecs
				decoder = codecs.lookup('utf-8')
				decex = decoder.decode(str(ex), errors = 'replace')[0]
				message += "\n\n(exact error: %s)" % decex

		SafeException.__init__(self, message)

	def __unicode__(self):
		if hasattr(SafeException, '__unicode__'):
			# Python >= 2.6
			if self.feed_url:
				return _('%s [%s]') % (SafeException.__unicode__(self), self.feed_url)
			return SafeException.__unicode__(self)
		else:
			return unicode(SafeException.__str__(self))

def _split_arch(arch):
	"""Split an arch into an (os, machine) tuple. Either or both parts may be None."""
	if not arch:
		return None, None
	elif '-' not in arch:
		raise SafeException(_("Malformed arch '%s'") % arch)
	else:
		osys, machine = arch.split('-', 1)
		if osys == '*': osys = None
		if machine == '*': machine = None
		return osys, machine

def _join_arch(osys, machine):
	if osys == machine == None: return None
	return "%s-%s" % (osys or '*', machine or '*')

def _best_language_match(options):
	(language, encoding) = locale.getlocale()

	if language:
		# xml:lang uses '-', while LANG uses '_'
		language = language.replace('_', '-')
	else:
		language = 'en-US'

	return (options.get(language, None) or			# Exact match (language+region)
		options.get(language.split('-', 1)[0], None) or	# Matching language
		options.get('en', None))			# English

class Stability(object):
	"""A stability rating. Each implementation has an upstream stability rating and,
	optionally, a user-set rating."""
	__slots__ = ['level', 'name', 'description']
	def __init__(self, level, name, description):
		self.level = level
		self.name = name
		self.description = description
		assert name not in stability_levels
		stability_levels[name] = self

	def __cmp__(self, other):
		return cmp(self.level, other.level)

	def __str__(self):
		return self.name

	def __repr__(self):
		return _("<Stability: %s>") % self.description

def process_binding(e):
	"""Internal"""
	if e.name == 'environment':
		mode = {
			None: EnvironmentBinding.PREPEND,
			'prepend': EnvironmentBinding.PREPEND,
			'append': EnvironmentBinding.APPEND,
			'replace': EnvironmentBinding.REPLACE,
		}[e.getAttribute('mode')]
			
		binding = EnvironmentBinding(e.getAttribute('name'),
					     insert = e.getAttribute('insert'),
					     default = e.getAttribute('default'),
					     value = e.getAttribute('value'),
					     mode = mode,
					     separator = e.getAttribute('separator'))
		if not binding.name: raise InvalidInterface(_("Missing 'name' in binding"))
		if binding.insert is None and binding.value is None:
			raise InvalidInterface(_("Missing 'insert' or 'value' in binding"))
		if binding.insert is not None and binding.value is not None:
			raise InvalidInterface(_("Binding contains both 'insert' and 'value'"))
		return binding
	elif e.name == 'overlay':
		return OverlayBinding(e.getAttribute('src'), e.getAttribute('mount-point'))
	else:
		raise Exception(_("Unknown binding type '%s'") % e.name)

def process_depends(item, local_feed_dir):
	"""Internal"""
	# Note: also called from selections
	attrs = item.attrs
	dep_iface = item.getAttribute('interface')
	if not dep_iface:
		raise InvalidInterface(_("Missing 'interface' on <%s>") % item.name)
	if dep_iface.startswith('./'):
		if local_feed_dir:
			dep_iface = os.path.abspath(os.path.join(local_feed_dir, dep_iface))
			# (updates the element too, in case we write it out again)
			attrs['interface'] = dep_iface
		else:
			raise InvalidInterface(_('Relative interface URI "%s" in non-local feed') % dep_iface)
	dependency = InterfaceDependency(dep_iface, element = item)

	for e in item.childNodes:
		if e.uri != XMLNS_IFACE: continue
		if e.name in binding_names:
			dependency.bindings.append(process_binding(e))
		elif e.name == 'version':
			dependency.restrictions.append(
				VersionRangeRestriction(not_before = parse_version(e.getAttribute('not-before')),
						        before = parse_version(e.getAttribute('before'))))
	return dependency

def N_(message): return message

insecure = Stability(0, N_('insecure'), _('This is a security risk'))
buggy = Stability(5, N_('buggy'), _('Known to have serious bugs'))
developer = Stability(10, N_('developer'), _('Work-in-progress - bugs likely'))
testing = Stability(20, N_('testing'), _('Stability unknown - please test!'))
stable = Stability(30, N_('stable'), _('Tested - no serious problems found'))
packaged = Stability(35, N_('packaged'), _('Supplied by the local package manager'))
preferred = Stability(40, N_('preferred'), _('Best of all - must be set manually'))

del N_

class Restriction(object):
	"""A Restriction limits the allowed implementations of an Interface."""
	__slots__ = []

	def meets_restriction(self, impl):
		"""Called by the L{solver.Solver} to check whether a particular implementation is acceptable.
		@return: False if this implementation is not a possibility
		@rtype: bool
		"""
		raise NotImplementedError(_("Abstract"))
	
class VersionRestriction(Restriction):
	"""Only select implementations with a particular version number.
	@since: 0.40"""

	def __init__(self, version):
		"""@param version: the required version number
		@see: L{parse_version}; use this to pre-process the version number
		"""
		self.version = version

	def meets_restriction(self, impl):
		return impl.version == self.version

	def __str__(self):
		return _("(restriction: version = %s)") % format_version(self.version)

class VersionRangeRestriction(Restriction):
	"""Only versions within the given range are acceptable"""
	__slots__ = ['before', 'not_before']

	def __init__(self, before, not_before):
		"""@param before: chosen versions must be earlier than this
		@param not_before: versions must be at least this high
		@see: L{parse_version}; use this to pre-process the versions
		"""
		self.before = before
		self.not_before = not_before
	
	def meets_restriction(self, impl):
		if self.not_before and impl.version < self.not_before:
			return False
		if self.before and impl.version >= self.before:
			return False
		return True
	
	def __str__(self):
		if self.not_before is not None or self.before is not None:
			range = ''
			if self.not_before is not None:
				range += format_version(self.not_before) + ' <= '
			range += 'version'
			if self.before is not None:
				range += ' < ' + format_version(self.before)
		else:
			range = 'none'
		return _("(restriction: %s)") % range

class Binding(object):
	"""Information about how the choice of a Dependency is made known
	to the application being run."""

class EnvironmentBinding(Binding):
	"""Indicate the chosen implementation using an environment variable."""
	__slots__ = ['name', 'insert', 'default', 'mode', 'value']

	PREPEND = 'prepend'
	APPEND = 'append'
	REPLACE = 'replace'

	def __init__(self, name, insert, default = None, mode = PREPEND,
              value=None, separator=None):
		"""
		mode argument added in version 0.28
		value argument added in version 0.52
		"""
		self.name = name
		self.insert = insert
		self.default = default
		self.mode = mode
		self.value = value
                if separator is None:
                    self.separator = os.pathsep
                else:
                    self.separator = separator

	
	def __str__(self):
		return _("<environ %(name)s %(mode)s %(insert)s %(value)s>") % {'name': self.name,'mode':  self.mode, 'insert': self.insert, 'value': self.value}

	__repr__ = __str__
	
	def get_value(self, path, old_value):
		"""Calculate the new value of the environment variable after applying this binding.
		@param path: the path to the selected implementation
		@param old_value: the current value of the environment variable
		@return: the new value for the environment variable"""

		if self.insert is not None:
			extra = os.path.join(path, self.insert)
		else:
			assert self.value is not None
			extra = self.value

		if self.mode == EnvironmentBinding.REPLACE:
			return extra

		if old_value is None:
			old_value = self.default or defaults.get(self.name, None)
		if old_value is None:
			return extra
		if self.mode == EnvironmentBinding.PREPEND:
			return extra + self.separator + old_value
		else:
			return old_value + self.separator + extra

	def _toxml(self, doc):
		"""Create a DOM element for this binding.
		@param doc: document to use to create the element
		@return: the new element
		"""
		env_elem = doc.createElementNS(XMLNS_IFACE, 'environment')
		env_elem.setAttributeNS(None, 'name', self.name)
		if self.insert is not None:
			env_elem.setAttributeNS(None, 'insert', self.insert)
		else:
			env_elem.setAttributeNS(None, 'value', self.value)
		if self.default:
			env_elem.setAttributeNS(None, 'default', self.default)
		return env_elem

class OverlayBinding(Binding):
	"""Make the chosen implementation available by overlaying it onto another part of the file-system.
	This is to support legacy programs which use hard-coded paths."""
	__slots__ = ['src', 'mount_point']

	def __init__(self, src, mount_point):
		self.src = src
		self.mount_point = mount_point

	def __str__(self):
		return _("<overlay %(src)s on %(mount_point)s>") % {'src': self.src or '.', 'mount_point': self.mount_point or '/'}

	__repr__ = __str__

	def _toxml(self, doc):
		"""Create a DOM element for this binding.
		@param doc: document to use to create the element
		@return: the new element
		"""
		env_elem = doc.createElementNS(XMLNS_IFACE, 'overlay')
		if self.src is not None:
			env_elem.setAttributeNS(None, 'src', self.src)
		if self.mount_point is not None:
			env_elem.setAttributeNS(None, 'mount-point', self.mount_point)
		return env_elem

class Feed(object):
	"""An interface's feeds are other interfaces whose implementations can also be
	used as implementations of this interface."""
	__slots__ = ['uri', 'os', 'machine', 'user_override', 'langs']
	def __init__(self, uri, arch, user_override, langs = None):
		self.uri = uri
		# This indicates whether the feed comes from the user's overrides
		# file. If true, writer.py will write it when saving.
		self.user_override = user_override
		self.os, self.machine = _split_arch(arch)
		self.langs = langs
	
	def __str__(self):
		return "<Feed from %s>" % self.uri
	__repr__ = __str__

	arch = property(lambda self: _join_arch(self.os, self.machine))

class Dependency(object):
	"""A Dependency indicates that an Implementation requires some additional
	code to function. This is an abstract base class.
	@ivar qdom: the XML element for this Dependency (since 0launch 0.51)
	@type qdom: L{qdom.Element}
	@ivar metadata: any extra attributes from the XML element
	@type metadata: {str: str}
	"""
	__slots__ = ['qdom']

	def __init__(self, element):
		assert isinstance(element, qdom.Element), type(element)	# Use InterfaceDependency instead!
		self.qdom = element

	@property
	def metadata(self):
		return self.qdom.attrs

class InterfaceDependency(Dependency):
	"""A Dependency on a Zero Install interface.
	@ivar interface: the interface required by this dependency
	@type interface: str
	@ivar restrictions: a list of constraints on acceptable implementations
	@type restrictions: [L{Restriction}]
	@ivar bindings: how to make the choice of implementation known
	@type bindings: [L{Binding}]
	@since: 0.28
	"""
	__slots__ = ['interface', 'restrictions', 'bindings']

	def __init__(self, interface, restrictions = None, element = None):
		Dependency.__init__(self, element)
		assert isinstance(interface, (str, unicode))
		assert interface
		self.interface = interface
		if restrictions is None:
			self.restrictions = []
		else:
			self.restrictions = restrictions
		self.bindings = []

	def __str__(self):
		return _("<Dependency on %(interface)s; bindings: %(bindings)s%(restrictions)s>") % {'interface': self.interface, 'bindings': self.bindings, 'restrictions': self.restrictions}

class RetrievalMethod(object):
	"""A RetrievalMethod provides a way to fetch an implementation."""
	__slots__ = []

	@tasks.async
	def retrieve(self, fetcher, destination, force = False, impl_hint = None):
		"""Retrieve implementation using method
		@param destination: where to put the retrieved files
		@param impl_hint: the Implementation this is for (if any) as a hint for the GUI
		"""
		raise NotImplementedError("abstract")

class DownloadSource(RetrievalMethod):
	"""A DownloadSource provides a way to fetch an implementation."""
	__slots__ = ['implementation', 'url', 'size', 'extract', 'start_offset', 'type']

	def __init__(self, implementation, url, size, extract, start_offset = 0, type = None):
		self.implementation = implementation
		self.url = url
		self.size = size
		self.extract = extract
		self.start_offset = start_offset
		self.type = type		# MIME type - see unpack.py

	@staticmethod
	def fromDOM(elem, impl):
		"""Make a DownloadSource from a DOM archive element."""
		url = elem.getAttribute('href')
		if not url:
			raise InvalidInterface(_("Missing href attribute on <archive>"))
		size = elem.getAttribute('size')
		if not size:
			raise InvalidInterface(_("Missing size attribute on <archive>"))

		return DownloadSource(impl, url = url, size = int(size), extract = elem.getAttribute('extract'),
			start_offset = _get_long(elem, 'start-offset'), type = elem.getAttribute('type'))

	def prepare(self, fetcher, force, impl_hint):

		class StepCommand(object):
			__slots__ = ['blocker', '_stream']

			def __init__(s):
				s.blocker, s._stream = self.download(fetcher, force = force, impl_hint = impl_hint)

			def run(s, destination):
				s._stream.seek(0)
				unpack.unpack_archive_over(self.url, s._stream, destination,
					extract = self.extract,
					type = self.type,
					start_offset = self.start_offset or 0)
		return StepCommand()

	def download(self, fetcher, force = False, impl_hint = None):
		"""Fetch an archive. You should normally call L{Implementation.retrieve}
		instead, since it handles other kinds of retrieval method too."""
		url = self.url
		if not (url.startswith('http:') or url.startswith('https:') or url.startswith('ftp:')):
			raise SafeException(_("Unknown scheme in download URL '%s'") % url)

		mime_type = self.type
		if not mime_type:
			mime_type = unpack.type_from_url(self.url)
		if not mime_type:
			raise SafeException(_("No 'type' attribute on archive, and I can't guess from the name (%s)") % self.url)
		unpack.check_type_ok(mime_type)
		dl = fetcher.handler.get_download(self.url, force = force, hint = impl_hint)
		dl.expected_size = self.size + (self.start_offset or 0)
		return (dl.downloaded, dl.tempfile)

	@tasks.async
	def retrieve(self, fetcher, destination, force = False, impl_hint = None):
		command = self.prepare(fetcher, force, impl_hint)
		yield command.blocker
		tasks.check(command.blocker)
		command.run(destination)


class UnpackArchive(object):
	"""An UnpackArchive step provides unpacks/extracts an archive.

	It can be used inside a Recipe."""
	__slots__ = ['path', 'extract', 'type']

	def __init__(self, path, extract, type):
		self.path = path
		self.extract = extract
		self.type = type

	def prepare(self, fetcher, force, impl_hint):

		class StepCommand(object):
			__slots__ = ['blocker']

			def __init__(s):
				s.blocker = None

			def run(s, tmpdir):
				path = os.path.join(tmpdir, self.path)
				stream = open(path, 'rb')
				stream.seek(0)

				unpack.unpack_archive_over(path, stream, tmpdir,
					extract = self.extract,
					type = self.type,
					start_offset = 0)

				os.unlink(path)

		return StepCommand()

class Recipe(RetrievalMethod):
	"""Get an implementation by following a series of steps.
	@ivar size: the combined download sizes from all the steps
	@type size: int
	@ivar steps: the sequence of steps which must be performed
	@type steps: [L{RetrievalMethod}]"""
	__slots__ = ['steps']

	def __init__(self):
		self.steps = []
	
	size = property(lambda self: sum([x.size for x in self.steps]))

	@tasks.async
	def retrieve(self, fetcher, destination, force = False, impl_hint = None):
		# Start preparing all steps
		step_commands = [step.prepare(fetcher, force, impl_hint) for step in self.steps]

		# Run steps
		valid_blockers = [s.blocker for s in step_commands if s.blocker is not None]
		for step_command in step_commands:
			if step_command.blocker:
				while not step_command.blocker.happened:
					yield valid_blockers
					tasks.check(valid_blockers)
			step_command.run(destination)

	@staticmethod
	def fromDOM(elem):
		"""Make a Recipe from a DOM recipe element"""
		recipe = Recipe()
		for recipe_step in elem.childNodes:
			if recipe_step.uri == XMLNS_IFACE and recipe_step.name == 'archive':
				recipe.steps.append(DownloadSource.fromDOM(recipe_step, None))
			elif recipe_step.uri == XMLNS_IFACE and recipe_step.name == 'unpack':
				path = recipe_step.getAttribute('path')
				if not path:
					raise InvalidInterface(_("Missing path attribute on <unpack>"))
				recipe.steps.append(UnpackArchive(path = path,
					extract = recipe_step.getAttribute('extract'),
					type = recipe_step.getAttribute('type')))
			else:
				info(_("Unknown step '%s' in recipe; skipping recipe"), recipe_step.name)
				return None
		else:
			return recipe

class DistributionSource(RetrievalMethod):
	"""A package that is installed using the distribution's tools (including PackageKit).
	@ivar install: a function to call to install this package
	@type install: (L{handler.Handler}) -> L{tasks.Blocker}
	@ivar package_id: the package name, in a form recognised by the distribution's tools
	@type package_id: str
	@ivar size: the download size in bytes
	@type size: int
	@ivar needs_confirmation: whether the user should be asked to confirm before calling install()
	@type needs_confirmation: bool"""

	__slots__ = ['package_id', 'size', 'install', 'needs_confirmation']

	def __init__(self, package_id, size, install, needs_confirmation = True):
		RetrievalMethod.__init__(self)
		self.package_id = package_id
		self.size = size
		self.install = install
		self.needs_confirmation = needs_confirmation

class Command(object):
	"""A Command is a way of running an Implementation as a program."""

	__slots__ = ['qdom', '_depends', '_local_dir', '_runner']

	def __init__(self, qdom, local_dir):
		"""@param qdom: the <command> element
		@param local_dir: the directory containing the feed (for relative dependencies), or None if not local
		"""
		assert qdom.name == 'command', 'not <command>: %s' % qdom
		self.qdom = qdom
		self._local_dir = local_dir
		self._depends = None

	path = property(lambda self: self.qdom.attrs.get("path", None))

	def _toxml(self, doc, prefixes):
		return self.qdom.toDOM(doc, prefixes)

	@property
	def requires(self):
		if self._depends is None:
			self._runner = None
			depends = []
			for child in self.qdom.childNodes:
				if child.name == 'requires':
					dep = process_depends(child, self._local_dir)
					depends.append(dep)
				elif child.name == 'runner':
					if self._runner:
						raise InvalidInterface(_("Multiple <runner>s in <command>!"))
					dep = process_depends(child, self._local_dir)
					depends.append(dep)
					self._runner = dep
			self._depends = depends
		return self._depends

	def get_runner(self):
		self.requires		# (sets _runner)
		return self._runner

class Implementation(object):
	"""An Implementation is a package which implements an Interface.
	@ivar download_sources: list of methods of getting this implementation
	@type download_sources: [L{RetrievalMethod}]
	@ivar feed: the feed owning this implementation (since 0.32)
	@type feed: [L{ZeroInstallFeed}]
	@ivar bindings: how to tell this component where it itself is located (since 0.31)
	@type bindings: [Binding]
	@ivar upstream_stability: the stability reported by the packager
	@type upstream_stability: [insecure | buggy | developer | testing | stable | packaged]
	@ivar user_stability: the stability as set by the user
	@type upstream_stability: [insecure | buggy | developer | testing | stable | packaged | preferred]
	@ivar langs: natural languages supported by this package
	@type langs: str
	@ivar requires: interfaces this package depends on
	@type requires: [L{Dependency}]
	@ivar commands: ways to execute as a program
	@type commands: {str: Command}
	@ivar metadata: extra metadata from the feed
	@type metadata: {"[URI ]localName": str}
	@ivar id: a unique identifier for this Implementation
	@ivar version: a parsed version number
	@ivar released: release date
	@ivar local_path: the directory containing this local implementation, or None if it isn't local (id isn't a path)
	@type local_path: str | None
	@ivar requires_root_install: whether the user will need admin rights to use this
	@type requires_root_install: bool
	"""

	# Note: user_stability shouldn't really be here

	__slots__ = ['upstream_stability', 'user_stability', 'langs',
		     'requires', 'metadata', 'download_sources', 'commands',
		     'id', 'feed', 'version', 'released', 'bindings', 'machine']

	def __init__(self, feed, id):
		self.feed = feed
		self.id = id
		self.user_stability = None
		self.upstream_stability = None
		self.metadata = {}	# [URI + " "] + localName -> value
		self.requires = []
		self.version = None
		self.released = None
		self.download_sources = []
		self.langs = ""
		self.machine = None
		self.bindings = []
		self.commands = {}

	def get_stability(self):
		return self.user_stability or self.upstream_stability or testing
	
	def __str__(self):
		return self.id

	def __repr__(self):
		return "v%s (%s)" % (self.get_version(), self.id)

	def __cmp__(self, other):
		"""Newer versions come first"""
		d = cmp(other.version, self.version)
		if d: return d
		# If the version number is the same, just give a stable sort order, and
		# ensure that two different implementations don't compare equal.
		d = cmp(other.feed.url, self.feed.url)
		if d: return d
		return cmp(other.id, self.id)

	def get_version(self):
		"""Return the version as a string.
		@see: L{format_version}
		"""
		return format_version(self.version)

	arch = property(lambda self: _join_arch(self.os, self.machine))

	os = None
	local_path = None
	digests = None
	requires_root_install = False

	def _get_main(self):
		""""@deprecated: use commands["run"] instead"""
		main = self.commands.get("run", None)
		if main is not None:
			return main.path
		return None
	def _set_main(self, path):
		""""@deprecated: use commands["run"] instead"""
		if path is None:
			if "run" in self.commands:
				del self.commands["run"]
		else:
			self.commands["run"] = Command(qdom.Element(XMLNS_IFACE, 'command', {'path': path}), None)
	main = property(_get_main, _set_main)

	def is_available(self, stores):
		"""Is this Implementation available locally?
		(a local implementation, an installed distribution package, or a cached ZeroInstallImplementation)
		@rtype: bool
		@since: 0.53
		"""
		raise NotImplementedError("abstract")

	@property
	def best_download_source(self):
		"""Return the best download source for this implementation.
		@rtype: L{model.RetrievalMethod}"""
		if self.download_sources:
			return self.download_sources[0]
		return None

	def retrieve(self, fetcher, retrieval_method, stores, force = False):
		"""Retrieve an implementation.
		@param retrieval_method: a way of getting the implementation (e.g. an Archive or a Recipe)
		@type retrieval_method: L{model.RetrievalMethod}
		@param stores: where to store the downloaded implementation
		@type stores: L{zerostore.Stores}
		@param force: whether to abort and restart an existing download
		@rtype: L{tasks.Blocker}"""
		raise NotImplementedError("abstract")

class DistributionImplementation(Implementation):
	"""An implementation provided by the distribution. Information such as the version
	comes from the package manager.
	@since: 0.28"""
	__slots__ = ['distro', 'installed']

	def __init__(self, feed, id, distro):
		assert id.startswith('package:')
		Implementation.__init__(self, feed, id)
		self.distro = distro
		self.installed = False

	@property
	def requires_root_install(self):
		return not self.installed

	def is_available(self, stores):
		return self.installed

	def retrieve(self, fetcher, retrieval_method, stores, force = False):
		return retrieval_method.install(fetcher.handler)


class ZeroInstallImplementation(Implementation):
	"""An implementation where all the information comes from Zero Install.
	@ivar digests: a list of "algorith=value" strings (since 0.45)
	@type digests: [str]
	@since: 0.28"""
	__slots__ = ['os', 'size', 'digests', 'local_path']

	def __init__(self, feed, id, local_path):
		"""id can be a local path (string starting with /) or a manifest hash (eg "sha1=XXX")"""
		if id:
			assert not id.startswith('package:'), id
		Implementation.__init__(self, feed, id)
		self.size = None
		self.os = None
		self.digests = []
		self.local_path = local_path

	@staticmethod
	def fromDOM(feed, item, item_attrs, local_dir, commands, bindings, depends, id_generation_alg=None, fetcher=None, stores=None):
		"""Make an implementation from a DOM implementation element.
		@param id_generation_alg: if specified, id will be autogenerated, if id is None, with this alg
		@type id_generation_alg: L{Algorithm}
		@param fetcher: must be specified if id_generation_alg is specified
		@param stores: must be specified if id_generation_alg is specified
		"""
		id = item.getAttribute('id')
		local_path = item_attrs.get('local-path')
		if local_dir and local_path:
			abs_local_path = os.path.abspath(os.path.join(local_dir, local_path))
			impl = ZeroInstallImplementation(feed, id, abs_local_path)
		elif local_dir and (id.startswith('/') or id.startswith('.')):
			# For old feeds
			id = os.path.abspath(os.path.join(local_dir, id))
			impl = ZeroInstallImplementation(feed, id, id)
		else:
			impl = ZeroInstallImplementation(feed, id, None)
			if id and '=' in id:
				# In older feeds, the ID was the (single) digest
				impl.digests.append(id)

		try:
			version_mod = item_attrs.get('version-modifier', None)
			if version_mod:
				item_attrs['version'] += version_mod
				del item_attrs['version-modifier']
			version = item_attrs['version']
		except KeyError:
			raise InvalidInterface(_("Missing version attribute"))
		impl.version = parse_version(version)

		impl.metadata = item_attrs
		impl.commands = commands
		impl.bindings = bindings
		impl.requires = depends
		impl.released = item_attrs.get('released', None)
		impl.langs = item_attrs.get('langs', '').replace('_', '-')

		size = item.getAttribute('size')
		if size:
			impl.size = int(size)

		impl.arch = item_attrs.get('arch', None)

		try:
			stability = stability_levels[str(item_attrs['stability'])]
		except KeyError:
			stab = str(item_attrs['stability'])
			if stab != stab.lower():
				raise InvalidInterface(_('Stability "%s" invalid - use lower case!') % item_attrs.stability)
			raise InvalidInterface(_('Stability "%s" invalid') % item_attrs['stability'])
		if stability >= preferred:
			raise InvalidInterface(_("Upstream can't set stability to preferred!"))
		impl.upstream_stability = stability

		for elem in item.childNodes:
			if elem.uri != XMLNS_IFACE: continue
			if elem.name == 'archive':
				impl.download_sources.append(DownloadSource.fromDOM(elem, impl))
			elif elem.name == 'manifest-digest':
				for aname, avalue in elem.attrs.iteritems():
					if ' ' not in aname:
						impl.digests.append('%s=%s' % (aname, avalue))
			elif elem.name == 'recipe':
				recipe = Recipe.fromDOM(elem)
				if recipe:
					impl.download_sources.append(recipe)

		if id is None and id_generation_alg:
			assert fetcher
			assert stores
			impl.id = impl._generate_digest(fetcher, stores, id_generation_alg)
		if impl.id is None:
			raise InvalidInterface(_("Missing 'id' attribute on %s") % item)

		return impl


	# Deprecated
	dependencies = property(lambda self: dict([(x.interface, x) for x in self.requires
						   if isinstance(x, InterfaceDependency)]))

	def add_download_source(self, url, size, extract, start_offset = 0, type = None):
		"""Add a download source."""
		# TODO should deprecate?
		self.download_sources.append(DownloadSource(self, url, size, extract, start_offset, type))

	def set_arch(self, arch):
		self.os, self.machine = _split_arch(arch)
	arch = property(lambda self: _join_arch(self.os, self.machine), set_arch)

	def is_available(self, stores):
		if self.local_path is not None:
			return os.path.exists(self.local_path)
		if self.digests:
			path = stores.lookup_maybe(self.digests)
			return path is not None
		return False	# (0compile creates fake entries with no digests)

	@property
	def best_digest(self):
		"""Return the best digest for this implementation
		@return: tuple (alg, digest) or None"""
		from zeroinstall.zerostore import manifest
		best_alg = None
		for digest in self.digests:
			alg_name = digest.split('=', 1)[0]
			alg = manifest.algorithms.get(alg_name, None)
			if alg and (best_alg is None or best_alg.rating < alg.rating):
				best_alg = alg
				best_digest = digest
		if best_alg:
			return (best_alg, best_digest)
		else:
			return None

	def _generate_digest(self, fetcher, stores, alg):
		digest = None

		# Create an empty directory for the new implementation
		store = stores.stores[0]
		tmpdir = store.get_tmp_dir_for('missing')

		try:
			blocker = self.best_download_source.retrieve(fetcher, tmpdir, force=False, impl_hint = self)
			tasks.wait_for_blocker(blocker)

			from zeroinstall.zerostore import manifest
			manifest.fixup_permissions(tmpdir)
			digest = alg.getID(manifest.add_manifest_file(tmpdir, alg))
		finally:
			# If unpacking fails, remove the temporary directory
			if tmpdir is not None:
				from zeroinstall import support
				support.ro_rmtree(tmpdir)

		return digest


	def retrieve(self, fetcher, retrieval_method, stores, force = False):
		best = self.best_digest

		if best is None:
			if not self.digests:
				raise SafeException(_("No <manifest-digest> given for '%(implementation)s' version %(version)s") %
						{'implementation': self.feed.get_name(), 'version': self.get_version()})
			raise SafeException(_("Unknown digest algorithms '%(algorithms)s' for '%(implementation)s' version %(version)s") %
					{'algorithms': self.digests, 'implementation': self.feed.get_name(), 'version': self.get_version()})
		else:
			alg, required_digest = best

		@tasks.async
		def retrieve():
			# Create an empty directory for the new implementation
			store = stores.stores[0]
			tmpdir = store.get_tmp_dir_for(required_digest)

			try:
				blocker = retrieval_method.retrieve(fetcher, tmpdir, force, impl_hint = self)
				yield blocker
				tasks.check(blocker)

				# Check that the result is correct and store it in the cache
				store.check_manifest_and_rename(required_digest, tmpdir)

				tmpdir = None
			finally:
				# If unpacking fails, remove the temporary directory
				if tmpdir is not None:
					from zeroinstall import support
					support.ro_rmtree(tmpdir)

			fetcher.handler.impl_added_to_store(self)

		return retrieve()


class Interface(object):
	"""An Interface represents some contract of behaviour.
	@ivar uri: the URI for this interface.
	@ivar stability_policy: user's configured policy.
	Implementations at this level or higher are preferred.
	Lower levels are used only if there is no other choice.
	"""
	__slots__ = ['uri', 'stability_policy', 'extra_feeds']

	implementations = property(lambda self: self._main_feed.implementations)
	name = property(lambda self: self._main_feed.name)
	description = property(lambda self: self._main_feed.description)
	summary = property(lambda self: self._main_feed.summary)
	last_modified = property(lambda self: self._main_feed.last_modified)
	feeds = property(lambda self: self.extra_feeds + self._main_feed.feeds)
	metadata = property(lambda self: self._main_feed.metadata)

	last_checked = property(lambda self: self._main_feed.last_checked)

	def __init__(self, uri):
		assert uri
		if uri.startswith('http:') or uri.startswith('https:') or os.path.isabs(uri):
			self.uri = uri
		else:
			raise SafeException(_("Interface name '%s' doesn't start "
					    "with 'http:' or 'https:'") % uri)
		self.reset()

	def _get_feed_for(self):
		retval = {}
		for key in self._main_feed.feed_for:
			retval[key] = True
		return retval
	feed_for = property(_get_feed_for)	# Deprecated (used by 0publish)

	def reset(self):
		self.extra_feeds = []
		self.stability_policy = None

	def get_name(self):
		from zeroinstall.injector.iface_cache import iface_cache
		feed = iface_cache.get_feed(self.uri)
		if feed:
			return feed.get_name()
		return '(' + os.path.basename(self.uri) + ')'
	
	def __repr__(self):
		return _("<Interface %s>") % self.uri
	
	def set_stability_policy(self, new):
		assert new is None or isinstance(new, Stability)
		self.stability_policy = new
	
	def get_feed(self, url):
		#import warnings
		#warnings.warn("use iface_cache.get_feed instead", DeprecationWarning, 2)
		for x in self.extra_feeds:
			if x.uri == url:
				return x
		#return self._main_feed.get_feed(url)
		return None
	
	def get_metadata(self, uri, name):
		return self._main_feed.get_metadata(uri, name)

	@property
	def _main_feed(self):
		#import warnings
		#warnings.warn("use the feed instead", DeprecationWarning, 3)
		from zeroinstall.injector import policy
		iface_cache = policy.get_deprecated_singleton_config().iface_cache
		feed = iface_cache.get_feed(self.uri)
		if feed is None:
			return _dummy_feed
		return feed

def _merge_attrs(attrs, item):
	"""Add each attribute of item to a copy of attrs and return the copy.
	@type attrs: {str: str}
	@type item: L{qdom.Element}
	@rtype: {str: str}
	"""
	new = attrs.copy()
	for a in item.attrs:
		new[str(a)] = item.attrs[a]
	return new

def _get_long(elem, attr_name):
	val = elem.getAttribute(attr_name)
	if val is not None:
		try:
			val = int(val)
		except ValueError:
			raise SafeException(_("Invalid value for integer attribute '%(attribute_name)s': %(value)s") % {'attribute_name': attr_name, 'value': val})
	return val

class ZeroInstallFeed(object):
	"""A feed lists available implementations of an interface.
	@ivar url: the URL for this feed
	@ivar implementations: Implementations in this feed, indexed by ID
	@type implementations: {str: L{Implementation}}
	@ivar name: human-friendly name
	@ivar summaries: short textual description (in various languages, since 0.49)
	@type summaries: {str: str}
	@ivar descriptions: long textual description (in various languages, since 0.49)
	@type descriptions: {str: str}
	@ivar last_modified: timestamp on signature
	@ivar last_checked: time feed was last successfully downloaded and updated
	@ivar feeds: list of <feed> elements in this feed
	@type feeds: [L{Feed}]
	@ivar feed_for: interfaces for which this could be a feed
	@type feed_for: set(str)
	@ivar metadata: extra elements we didn't understand
	"""
	# _main is deprecated
	__slots__ = ['url', 'implementations', 'name', 'descriptions', 'first_description', 'summaries', 'first_summary', '_package_implementations',
		     'last_checked', 'last_modified', 'feeds', 'feed_for', 'metadata']

	def __init__(self, feed_element, local_path = None, distro = None, 
			implementation_id_alg=None, fetcher=None, stores=None):
		"""Create a feed object from a DOM.
		@param feed_element: the root element of a feed file
		@type feed_element: L{qdom.Element}
		@param local_path: the pathname of this local feed, or None for remote feeds
		@param implementation_id_alg: if specified, missing impl ids will be generated with this alg
		@type implementation_id_alg: L{Algorithm}
		@param fetcher: cannot be None if implementation_id_alg is specified
		@param stores: cannot be None if implementation_id_alg is specified"""
		self.implementations = {}
		self.name = None
		self.summaries = {}	# { lang: str }
		self.first_summary = None
		self.descriptions = {}	# { lang: str }
		self.first_description = None
		self.last_modified = None
		self.feeds = []
		self.feed_for = set()
		self.metadata = []
		self.last_checked = None
		self._package_implementations = []

		if distro is not None:
			import warnings
			warnings.warn("distro argument is now ignored", DeprecationWarning, 2)

		if feed_element is None:
			return			# XXX subclass?

		assert feed_element.name in ('interface', 'feed'), "Root element should be <interface>, not %s" % feed_element
		assert feed_element.uri == XMLNS_IFACE, "Wrong namespace on root element: %s" % feed_element.uri

		main = feed_element.getAttribute('main')
		#if main: warn("Setting 'main' on the root element is deprecated. Put it on a <group> instead")

		if local_path:
			self.url = local_path
			local_dir = os.path.dirname(local_path)
		else:
			self.url = feed_element.getAttribute('uri')
			if not self.url:
				raise InvalidInterface(_("<interface> uri attribute missing"))
			local_dir = None	# Can't have relative paths

		min_injector_version = feed_element.getAttribute('min-injector-version')
		if min_injector_version:
			if parse_version(min_injector_version) > parse_version(version):
				raise InvalidInterface(_("This feed requires version %(min_version)s or later of "
							"Zero Install, but I am only version %(version)s. "
							"You can get a newer version from http://0install.net") %
							{'min_version': min_injector_version, 'version': version})

		for x in feed_element.childNodes:
			if x.uri != XMLNS_IFACE:
				self.metadata.append(x)
				continue
			if x.name == 'name':
				self.name = x.content
			elif x.name == 'description':
				if self.first_description == None:
					self.first_description = x.content
				self.descriptions[x.attrs.get("http://www.w3.org/XML/1998/namespace lang", 'en')] = x.content
			elif x.name == 'summary':
				if self.first_summary == None:
					self.first_summary = x.content
				self.summaries[x.attrs.get("http://www.w3.org/XML/1998/namespace lang", 'en')] = x.content
			elif x.name == 'feed-for':
				feed_iface = x.getAttribute('interface')
				if not feed_iface:
					raise InvalidInterface(_('Missing "interface" attribute in <feed-for>'))
				self.feed_for.add(feed_iface)
				# Bug report from a Debian/stable user that --feed gets the wrong value.
				# Can't reproduce (even in a Debian/stable chroot), but add some logging here
				# in case it happens again.
				debug(_("Is feed-for %s"), feed_iface)
			elif x.name == 'feed':
				feed_src = x.getAttribute('src')
				if not feed_src:
					raise InvalidInterface(_('Missing "src" attribute in <feed>'))
				if feed_src.startswith('http:') or feed_src.startswith('https:') or local_path:
					langs = x.getAttribute('langs')
					if langs: langs = langs.replace('_', '-')
					self.feeds.append(Feed(feed_src, x.getAttribute('arch'), False, langs = langs))
				else:
					raise InvalidInterface(_("Invalid feed URL '%s'") % feed_src)
			else:
				self.metadata.append(x)

		if not self.name:
			raise InvalidInterface(_("Missing <name> in feed"))
		if not self.summary:
			raise InvalidInterface(_("Missing <summary> in feed"))

		def process_group(group, group_attrs, base_depends, base_bindings, base_commands):
			for item in group.childNodes:
				if item.uri != XMLNS_IFACE: continue

				if item.name not in ('group', 'implementation', 'package-implementation'):
					continue

				# We've found a group or implementation. Scan for dependencies,
				# bindings and commands. Doing this here means that:
				# - We can share the code for groups and implementations here.
				# - The order doesn't matter, because these get processed first.
				# A side-effect is that the document root cannot contain
				# these.

				depends = base_depends[:]
				bindings = base_bindings[:]
				commands = base_commands.copy()

				for attr, command in [('main', 'run'),
						      ('self-test', 'test')]:
					value = item.attrs.get(attr, None)
					if value is not None:
						commands[command] = Command(qdom.Element(XMLNS_IFACE, 'command', {'path': value}), None)

				for child in item.childNodes:
					if child.uri != XMLNS_IFACE: continue
					if child.name == 'requires':
						dep = process_depends(child, local_dir)
						depends.append(dep)
					elif child.name == 'command':
						command_name = child.attrs.get('name', None)
						if not command_name:
							raise InvalidInterface('Missing name for <command>')
						commands[command_name] = Command(child, local_dir)
					elif child.name in binding_names:
						bindings.append(process_binding(child))

				compile_command = item.attrs.get('http://zero-install.sourceforge.net/2006/namespaces/0compile command')
				if compile_command is not None:
					commands['compile'] = Command(qdom.Element(XMLNS_IFACE, 'command', {'shell-command': compile_command}), None)

				item_attrs = _merge_attrs(group_attrs, item)

				if item.name == 'group':
					process_group(item, item_attrs, depends, bindings, commands)
				elif item.name == 'implementation':
					impl = ZeroInstallImplementation.fromDOM(self, item, item_attrs, local_dir, commands, bindings, depends,
							implementation_id_alg, fetcher, stores)
					if impl.id in self.implementations:
						warn(_("Duplicate ID '%(id)s' in feed '%(feed)s'"), {'id': id, 'feed': self})
					self.implementations[impl.id] = impl
				elif item.name == 'package-implementation':
					if depends:
						warn("A <package-implementation> with dependencies in %s!", self.url)
					self._package_implementations.append((item, item_attrs))
				else:
					assert 0

		root_attrs = {'stability': 'testing'}
		root_commands = {}
		if main:
			info("Note: @main on document element is deprecated in %s", self)
			root_commands['run'] = Command(qdom.Element(XMLNS_IFACE, 'command', {'path': main}), None)
		process_group(feed_element, root_attrs, [], [], root_commands)
	
	def get_distro_feed(self):
		"""Does this feed contain any <pacakge-implementation> elements?
		i.e. is it worth asking the package manager for more information?
		@return: the URL of the virtual feed, or None
		@since: 0.49"""
		if self._package_implementations:
			return "distribution:" + self.url
		return None

	def get_package_impls(self, distro):
		"""Find the best <pacakge-implementation> element(s) for the given distribution.
		@param distro: the distribution to use to rate them
		@type distro: L{distro.Distribution}
		@return: a list of tuples for the best ranked elements
		@rtype: [str]
		@since: 0.49"""
		best_score = 0
		best_impls = []

		for item, item_attrs in self._package_implementations:
			distro_names = item_attrs.get('distributions', '')
			for distro_name in distro_names.split(' '):
				score = distro.get_score(distro_name)
				if score > best_score:
					best_score = score
					best_impls = []
				if score == best_score:
					best_impls.append((item, item_attrs))
		return best_impls

	def get_name(self):
		return self.name or '(' + os.path.basename(self.url) + ')'
	
	def __repr__(self):
		return _("<Feed %s>") % self.url
	
	def set_stability_policy(self, new):
		assert new is None or isinstance(new, Stability)
		self.stability_policy = new
	
	def get_feed(self, url):
		for x in self.feeds:
			if x.uri == url:
				return x
		return None
	
	def add_metadata(self, elem):
		self.metadata.append(elem)
	
	def get_metadata(self, uri, name):
		"""Return a list of interface metadata elements with this name and namespace URI."""
		return [m for m in self.metadata if m.name == name and m.uri == uri]

	@property
	def summary(self):
		return _best_language_match(self.summaries) or self.first_summary

	@property
	def description(self):
		return _best_language_match(self.descriptions) or self.first_description

class DummyFeed(object):
	"""Temporary class used during API transition."""
	last_modified = None
	name = '-'
	last_checked = property(lambda self: None)
	implementations = property(lambda self: {})
	feeds = property(lambda self: [])
	summary = property(lambda self: '-')
	description = property(lambda self: '')
	def get_name(self): return self.name
	def get_feed(self, url): return None
	def get_metadata(self, uri, name): return []
_dummy_feed = DummyFeed()

def unescape(uri):
	"""Convert each %20 to a space, etc.
	@rtype: str"""
	uri = uri.replace('#', '/')
	if '%' not in uri: return uri
	return re.sub('%[0-9a-fA-F][0-9a-fA-F]',
		lambda match: chr(int(match.group(0)[1:], 16)),
		uri).decode('utf-8')

def escape(uri):
	"""Convert each space to %20, etc
	@rtype: str"""
	return re.sub('[^-_.a-zA-Z0-9]',
		lambda match: '%%%02x' % ord(match.group(0)),
		uri.encode('utf-8'))

def _pretty_escape(uri):
	"""Convert each space to %20, etc
	: is preserved and / becomes #. This makes for nicer strings,
	and may replace L{escape} everywhere in future.
	@rtype: str"""
	if os.name == "posix":
		# Only preserve : on Posix systems
		preserveRegex = '[^-_.a-zA-Z0-9:/]'
	else:
		# Other OSes may not allow the : character in file names
		preserveRegex = '[^-_.a-zA-Z0-9/]'
	return re.sub(preserveRegex,
		lambda match: '%%%02x' % ord(match.group(0)),
		uri.encode('utf-8')).replace('/', '#')

def canonical_iface_uri(uri):
	"""If uri is a relative path, convert to an absolute one.
	A "file:///foo" URI is converted to "/foo".
	An "alias:prog" URI expands to the URI in the 0alias script
	Otherwise, return it unmodified.
	@rtype: str
	@raise SafeException: if uri isn't valid
	"""
	if uri.startswith('http://') or uri.startswith('https://'):
		if uri.count("/") < 3:
			raise SafeException(_("Missing / after hostname in URI '%s'") % uri)
		return uri
	elif uri.startswith('file:///'):
		return uri[7:]
	elif uri.startswith('alias:'):
		from zeroinstall import alias, support
		alias_prog = uri[6:]
		if not os.path.isabs(alias_prog):
			full_path = support.find_in_path(alias_prog)
			if not full_path:
				raise alias.NotAnAliasScript("Not found in $PATH: " + alias_prog)
		else:
			full_path = alias_prog
		interface_uri, main = alias.parse_script(full_path)
		return interface_uri
	else:
		iface_uri = os.path.realpath(uri)
		if os.path.isfile(iface_uri):
			return iface_uri
	raise SafeException(_("Bad interface name '%(uri)s'.\n"
			"(doesn't start with 'http:', and "
			"doesn't exist as a local file '%(interface_uri)s' either)") %
			{'uri': uri, 'interface_uri': iface_uri})

_version_mod_to_value = {
	'pre': -2,
	'rc': -1,
	'': 0,
	'post': 1,
}

# Reverse mapping
_version_value_to_mod = {}
for x in _version_mod_to_value: _version_value_to_mod[_version_mod_to_value[x]] = x
del x

_version_re = re.compile('-([a-z]*)')

def parse_version(version_string):
	"""Convert a version string to an internal representation.
	The parsed format can be compared quickly using the standard Python functions.
	 - Version := DottedList ("-" Mod DottedList?)*
	 - DottedList := (Integer ("." Integer)*)
	@rtype: tuple (opaque)
	@raise SafeException: if the string isn't a valid version
	@since: 0.24 (moved from L{reader}, from where it is still available):"""
	if version_string is None: return None
	parts = _version_re.split(version_string)
	if parts[-1] == '':
		del parts[-1]	# Ends with a modifier
	else:
		parts.append('')
	if not parts:
		raise SafeException(_("Empty version string!"))
	l = len(parts)
	try:
		for x in range(0, l, 2):
			part = parts[x]
			if part:
				parts[x] = map(int, parts[x].split('.'))
			else:
				parts[x] = []	# (because ''.split('.') == [''], not [])
		for x in range(1, l, 2):
			parts[x] = _version_mod_to_value[parts[x]]
		return parts
	except ValueError, ex:
		raise SafeException(_("Invalid version format in '%(version_string)s': %(exception)s") % {'version_string': version_string, 'exception': ex})
	except KeyError, ex:
		raise SafeException(_("Invalid version modifier in '%(version_string)s': %(exception)s") % {'version_string': version_string, 'exception': ex})

def format_version(version):
	"""Format a parsed version for display. Undoes the effect of L{parse_version}.
	@see: L{Implementation.get_version}
	@rtype: str
	@since: 0.24"""
	version = version[:]
	l = len(version)
	for x in range(0, l, 2):
		version[x] = '.'.join(map(str, version[x]))
	for x in range(1, l, 2):
		version[x] = '-' + _version_value_to_mod[version[x]]
	if version[-1] == '-': del version[-1]
	return ''.join(version)

