import logging
import socket
from typing import List, Optional, Dict, Any
from impacket.smbconnection import SMBConnection
from .session import SMBSession

logger = logging.getLogger(__name__)

class SMBClient:
    """High-level wrapper for SMB operations using impacket."""
    
    def __init__(self, target: str, port: int = 445, timeout: int = 10):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.connection: Optional[SMBConnection] = None
        self.session: Optional[SMBSession] = None

    def connect(self, session: SMBSession) -> bool:
        """Establishes an SMB connection and authenticates."""
        try:
            self.session = session
            self.connection = SMBConnection(
                self.target, 
                self.target, 
                sess_port=self.port, 
                timeout=self.timeout
            )
            
            if session.use_guest or session.is_anonymous:
                self.connection.login('', '')
            else:
                self.connection.login(
                    session.username,
                    session.password,
                    domain=session.domain,
                    lmhash=session.lmhash,
                    nthash=session.nthash
                )
            
            logger.info(f"Successfully authenticated to {self.target}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect/authenticate to {self.target}: {e}")
            self.connection = None
            return False

    def list_shares(self) -> List[Dict[str, Any]]:
        """Lists available shares on the target."""
        if not self.connection:
            return []
        
        try:
            shares = self.connection.listShares()
            return [
                {
                    "name": share['shi1_netname'][:-1],
                    "type": share['shi1_type'],
                    "remark": share['shi1_remark'][:-1]
                }
                for share in shares
            ]
        except Exception as e:
            logger.error(f"Failed to list shares on {self.target}: {e}")
            return []

    def list_files(self, share_name: str, path: str = "*", recursive: bool = False) -> List[Dict[str, Any]]:
        """Lists files and directories in a given share and path."""
        if not self.connection:
            return []

        files = []
        try:
            # Impacket's listPath handles wildcards
            items = self.connection.listPath(share_name, path)
            for item in items:
                # Skip . and ..
                if item.get_longname() in [".", ".."]:
                    continue
                
                file_info = {
                    "name": item.get_longname(),
                    "is_directory": item.is_directory(),
                    "size": item.get_filesize(),
                    "mtime": item.get_mtime(),
                    "share": share_name
                }
                files.append(file_info)
                
                if recursive and item.is_directory():
                    # Construct subpath carefully
                    sub_path = f"{path.rstrip('*').rstrip('/')}/{item.get_longname()}/*"
                    files.extend(self.list_files(share_name, sub_path, recursive=True))
                    
            return files
        except Exception as e:
            logger.error(f"Failed to list files in {share_name}:{path}: {e}")
            return files

    def get_file_content(self, share_name: str, file_path: str) -> bytes:
        """Retrieves the content of a file from a share."""
        if not self.connection:
            return b""
            
        import io
        file_obj = io.BytesIO()
        try:
            self.connection.getFile(share_name, file_path, file_obj.write)
            return file_obj.getvalue()
        except Exception as e:
            logger.error(f"Failed to get file content from {share_name}:{file_path}: {e}")
            return b""

    def disconnect(self):
        """Closes the SMB connection."""
        if self.connection:
            try:
                self.connection.logoff()
            except:
                pass
            self.connection = None
