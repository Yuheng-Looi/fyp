"""Runtime compatibility patches for legacy Ryu on modern Python."""

import builtins
builtins.buffer = memoryview

try:
    import threading
    from mininet.node import Node
    _node_cmd_lock = threading.Lock()
    _orig_node_cmd = Node.cmd
    def _thread_safe_cmd(self, *args, **kwargs):
        with _node_cmd_lock:
            return _orig_node_cmd(self, *args, **kwargs)
    Node.cmd = _thread_safe_cmd
except ImportError:
    pass

import ryu.utils
ryu.utils.round_up = lambda x, y: ((x + y - 1) // y) * y

import ryu.lib.addrconv
_orig_text_to_bin = ryu.lib.addrconv.AddressConverter.text_to_bin
def _patched_text_to_bin(self, text):
    if isinstance(text, bytes):
        text = text.decode('ascii')
    return _orig_text_to_bin(self, text)
ryu.lib.addrconv.AddressConverter.text_to_bin = _patched_text_to_bin

import ryu.ofproto.oxm_fields
def _patched_from_user(self, i):
    res = []
    for _ in range(self.size):
        res.append(i & 255)
        i //= 256
    res.reverse()
    return bytes(res)
ryu.ofproto.oxm_fields.IntDescr.from_user = _patched_from_user

import importlib.abc
import importlib.machinery
import sys


_TARGET = "ryu.base.app_manager"


def _patch_app_manager(module):
    app_manager = getattr(module, "AppManager", None)
    if app_manager is None or getattr(app_manager, "_benchmark_py311_patched", False):
        return

    def instantiate_apps(self, *args, **kwargs):
        for app_name, cls in list(self.applications_cls.items()):
            module.LOG.info("instantiating app %s", app_name)

            if hasattr(cls, "OFP_VERSIONS"):
                for version in list(module.Datapath.supported_ofp_version.keys()):
                    if version not in cls.OFP_VERSIONS:
                        del module.Datapath.supported_ofp_version[version]

            assert len(module.Datapath.supported_ofp_version), "No OpenFlow version is available"
            assert app_name not in self.applications
            app = cls(*args, **kwargs)
            module.register_app(app)
            self.applications[app_name] = app

        for service in list(module.SERVICE_BRICKS.values()):
            for _key, method in module.inspect.getmembers(service, module.inspect.ismethod):
                if not hasattr(method, "observer"):
                    continue

                name = method.observer.split(".")[-1]
                if name in module.SERVICE_BRICKS:
                    brick = module.SERVICE_BRICKS[name]
                    brick.register_observer(method.ev_cls, service.name, method.dispatchers)

                for brick in list(module.SERVICE_BRICKS.values()):
                    if method.ev_cls in brick._EVENTS:
                        brick.register_observer(method.ev_cls, service.name, method.dispatchers)

        for brick, service in list(module.SERVICE_BRICKS.items()):
            module.LOG.debug("BRICK %s" % brick)
            for ev_cls, observers in list(service.observers.items()):
                module.LOG.debug("  PROVIDES %s TO %s" % (ev_cls.__name__, observers))
            for ev_cls in list(service.event_handlers.keys()):
                module.LOG.debug("  CONSUMES %s" % (ev_cls.__name__,))

    app_manager.instantiate_apps = instantiate_apps
    app_manager._benchmark_py311_patched = True


class _RyuPatchLoader(importlib.abc.Loader):
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def create_module(self, spec):
        create_module = getattr(self._wrapped, "create_module", None)
        if create_module is None:
            return None
        return create_module(spec)

    def exec_module(self, module):
        self._wrapped.exec_module(module)
        _patch_app_manager(module)


class _RyuPatchFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname != _TARGET:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        if spec is None or spec.loader is None:
            return spec
        spec.loader = _RyuPatchLoader(spec.loader)
        return spec


if _TARGET in sys.modules:
    _patch_app_manager(sys.modules[_TARGET])
else:
    sys.meta_path.insert(0, _RyuPatchFinder())
