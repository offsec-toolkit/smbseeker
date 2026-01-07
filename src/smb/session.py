import logging
from typing import List, Optional
from impacket.smbconnection import SMBConnection
from impacket.ntlm import compute_lm_hash, compute_nt_hash

logger = logging.getLogger(__name__)

class SMBSession:
    """Manages SMB session credentials and authentication."""
    
    def __init__(
        self,
        username: str = "",
        password: str = "",
        domain: str = "",
        nthash: str = "",
        lmhash: str = "",
        use_guest: bool = False
    ):
        self.username = username
        self.password = password
        self.domain = domain
        self.nthash = nthash
        self.lmhash = lmhash
        self.use_guest = use_guest

    @property
    def is_anonymous(self) -> bool:
        return not self.username and not self.password and not self.nthash

    def __repr__(self):
        return f"SMBSession(user={self.username or 'guest'}, domain={self.domain})"
