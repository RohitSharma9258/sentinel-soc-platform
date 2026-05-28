"""
Smart WiFi Intruder Detection System - Network Context
Single source of truth for network state: gateway, 
local IP, subnet. All modules import from here.
"""

import logging
import threading
import time
from utils import get_local_ip, get_default_gateway, get_network_cidr
from config import FORCE_LOCAL_IP, FORCE_NETWORK

logger = logging.getLogger("network_ctx")

class NetworkContext:
    """
    Singleton that holds and refreshes network state.
    All modules should import 'net_ctx' and use:
        net_ctx.gateway_ip
        net_ctx.local_ip  
        net_ctx.network_cidr
    Instead of calling utils functions directly.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
                # ARCH: Safe initialization defaults to prevent AttributeError on early accesses
                cls._instance._local_ip = None
                cls._instance._gateway_ip = None
                cls._instance._network_cidr = None
                cls._instance._last_refresh = 0
                cls._instance._refresh_interval = 300
        return cls._instance
    
    def initialize(self, refresh_interval=300):
        """Initialize and start auto-refresh with thread safety."""
        with self._lock:
            if self._initialized:
                return
            self._refresh_interval = refresh_interval
            self._local_ip = None
            self._gateway_ip = None
            self._network_cidr = None
            self._last_refresh = 0
            self._refresh()
            self._initialized = True
            logger.info(
                f"NetworkContext initialized successfully: "
                f"local={self._local_ip}, "
                f"gateway={self._gateway_ip}, "
                f"network={self._network_cidr}"
            )
    
    def _refresh(self):
        """Refresh all network values."""
        try:
            self._local_ip = FORCE_LOCAL_IP or get_local_ip()
            self._gateway_ip = get_default_gateway(validate=False)
            self._network_cidr = FORCE_NETWORK or get_network_cidr()
            self._last_refresh = time.time()
            logger.debug(f"NetworkContext refreshed: {self._network_cidr}")
        except Exception as e:
            logger.error(f"NetworkContext refresh failed: {e}")
    
    def _maybe_refresh(self):
        """Refresh if TTL expired."""
        if time.time() - self._last_refresh > self._refresh_interval:
            self._refresh()
    
    @property
    def is_initialized(self) -> bool:
        """Check if the NetworkContext has been explicitly initialized."""
        return self._initialized

    @property
    def local_ip(self) -> str:
        if not self._initialized:
            raise UninitializedNetworkContextError("Cannot access local_ip: NetworkContext is not initialized.")
        self._maybe_refresh()
        return self._local_ip or "127.0.0.1"
    
    @property
    def gateway_ip(self) -> str:
        if not self._initialized:
            raise UninitializedNetworkContextError("Cannot access gateway_ip: NetworkContext is not initialized.")
        self._maybe_refresh()
        return self._gateway_ip or "192.168.1.1"
    
    @property
    def network_cidr(self) -> str:
        if not self._initialized:
            raise UninitializedNetworkContextError("Cannot access network_cidr: NetworkContext is not initialized.")
        self._maybe_refresh()
        if not self._network_cidr:
            raise RuntimeError("NetworkContext is initialized but network_cidr is unresolved.")
        return self._network_cidr
    
    def force_refresh(self):
        """Force immediate refresh (call after network change)."""
        with self._lock:
            self._last_refresh = 0
            self._refresh()
            logger.info("NetworkContext force-refreshed")
    
    def to_dict(self) -> dict:
        return {
            "local_ip": self.local_ip,
            "gateway_ip": self.gateway_ip,
            "network_cidr": self.network_cidr,
            "last_refresh": self._last_refresh,
        }

class UninitializedNetworkContextError(RuntimeError):
    """Exception raised when accessing NetworkContext properties before initialization."""
    pass

# Module singleton
net_ctx = NetworkContext()

