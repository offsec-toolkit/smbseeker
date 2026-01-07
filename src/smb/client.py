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

    import time

    def connect(self, session: SMBSession, retries: int = 3, delay: int = 2) -> bool:
        """Establishes an SMB connection and authenticates with retry logic."""
        self.session = session
        attempt = 0
        
        while attempt < retries:
            try:
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
                
                logger.info(f"Successfully authenticated to {self.target} (Attempt {attempt + 1})")
                return True
            except (socket.timeout, TimeoutError):
                attempt += 1
                logger.warning(f"Host {self.target} timeout, retrying... ({attempt}/{retries})")
                if attempt < retries:
                    time.sleep(delay)
            except Exception as e:
                logger.error(f"Failed to connect/authenticate to {self.target}: {e}")
                # Potentially add downgrade logic here if needed for older SMB versions
                # For now, we stop on fatal errors unless it's a timeout
                break
        
        self.connection = None
        return False

    def list_shares(self) -> List[Dict[str, Any]]:
        """Lists available shares on the target."""
        if not self.connection:
            return []
        
        try:
            shares = self.connection.listShares()
            results = []
            for share in shares:
                # Robustly extract name, ignoring potential null terminators
                name = share['shi1_netname'].rstrip('\x00')
                remark = share['shi1_remark'].rstrip('\x00')
                results.append({
                    "name": name,
                    "type": share['shi1_type'],
                    "remark": remark
                })
            return results
        except Exception as e:
            logger.error(f"Failed to list shares on {self.target}: {e}")
            return []

    def list_files(self, share_name: str, path: str = "*", recursive: bool = False) -> List[Dict[str, Any]]:
        """Lists files and directories in a given share and path."""
        if not self.connection:
            return []

        files = []
        try:
            # Normalize path for impacket (ensuring it's not starting with /)
            search_path = path.replace('/', '\\')
            items = self.connection.listPath(share_name, search_path)
            
            for item in items:
                long_name = item.get_longname()
                if long_name in [".", ".."]:
                    continue
                
                # Calculate the clean path for the current item
                # Remove trailing wildcard for the base directory
                base_dir = search_path.rstrip('*').rstrip('\\')
                item_full_path = f"{base_dir}\\{long_name}" if base_dir else long_name
                
                file_info = {
                    "name": long_name,
                    "path": item_full_path,
                    "is_directory": item.is_directory(),
                    "size": item.get_filesize(),
                    "mtime": item.get_mtime(),
                    "share": share_name
                }
                files.append(file_info)
                
                if recursive and item.is_directory():
                    sub_search = f"{item_full_path}\\*"
                    files.extend(self.list_files(share_name, sub_search, recursive=True))
                    
            return files
        except Exception as e:
            logger.error(f"Failed to list files in {share_name}:{path}: {e}")
            return files

    def get_file_content(self, share_name: str, file_path: str, max_size: int = 1024 * 1024) -> bytes:
        """Retrieves the content (or partial content) of a file from a share."""
        if not self.connection:
            return b""
            
        import io
        file_obj = io.BytesIO()
        try:
            # Use getFile but we should ideally use a more granular read if we want to limit size properly
            # Impacket's getFile takes a callback/file-like object. 
            # To be truly safe with large files, we'd use openFile/read
            
            # Simple workaround: we read everything, but we expect the caller to check size first.
            # For better QA, let's implement a size-safe read.
            
            tid = self.connection.connectTree(share_name)
            fid = self.connection.openFile(tid, file_path)
            content = self.connection.readFile(tid, fid, offset=0, bytesToRead=max_size)
            self.connection.closeFile(tid, fid)
            return content
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
