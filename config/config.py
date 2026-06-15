import os
import configparser
import  json
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, Column, String, Integer, text
from sqlalchemy.ext.declarative import declarative_base
import os
from datetime import datetime
from utils.utils import ensure_directory_exists, get_md5_prefix,upsert_ProjectInfo_data
HOME = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GHIDRA_SCRIPT_ROOT_PATH = os.path.join(HOME)
# ghidra path
HEADLESS_GHIDRA = os.path.join(HOME, "ghidra", "support", "analyzeHeadless")
# ghidra script path
GHIDRA_SCRIPT = os.path.join(HOME, "headless")
_engine = None
_Session = None
Base = declarative_base()
lib_sink = None


class ProjectInfo(Base):
    """
    ORM mapping for project_info table.
    """
    __tablename__ = 'project_info'
    tag = Column(String, primary_key=True)
    data = Column(String)

class LibUnsafeResJson(Base):
    """
    ORM mapping for lib_unsafe_res_json table.
    """
    __tablename__ = 'lib_unsafe_res_json'
    lib_file_name = Column(String, primary_key=True)
    result_json = Column(String)

class LibDecompileResJson(Base):
    """
    ORM mapping for lib_unsafe_res_json table.
    """
    __tablename__ = 'lib_decompile_res'
    id = Column(Integer, primary_key=True, autoincrement=True)  # ID with autoincrement
    lib_name = Column(String, nullable=False)  # Library name
    func_name = Column(String, nullable=False)  # Function name
    func_addr = Column(String, nullable=False)  # Function name
    decompiled_code = Column(String, nullable=False)  # Decompiled function code


class Config:
    def __init__(self, config_file='config/config.ini'):
        """
        Initializes the configuration object and loads the specified config file.
        :param config_file: Path to the config file, default is 'vul_functions.ini'
        """
        # Load the config file
        self.config = self.load_config(config_file)
        self.scripts = self.generate_scripts_config()
        self.vfuncParam = self.load_vfuncParam()
        self.project_name = None
        self.project_path = None
        self.binary_path = None
        self.lib_path = f"result/{self.config['ResultDir']['lib_path']}"
        self.directory_map = None
        self.other_config = {}
        self.main_project_name = None
        self.main_file_name = None
        self.db_path = None
        self.device = None
        self.source_point = []
        self.sink_point = []

    def set_device_info(self, device):
        self.device = device
        self.project_path = device
        self.db_path = f"result/{device}/ghidra_analyze_res.db"

    def init_db(self):
        session = self.get_db_session(Base)
        # new_entry = ProjectInfo(tag="LastTime", data=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        tag = "LastTime"
        data = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        upsert_ProjectInfo_data(tag, data)

    
    def get_db_session(self, Base):
        """
        Lazily initialize and return a SQLAlchemy session.
        """
        global _engine, _Session
        if _engine is None or _Session is None:
            _engine = create_engine(f"sqlite:///{self.db_path}")
            Base.metadata.create_all(_engine)
            _Session = sessionmaker(bind=_engine)
        return _Session()

    def set_binary_path(self, binary_path, main_file):
        self.binary_path = binary_path
        self.set_project_name(main_file)
        
    def set_project_name(self, main_file):
        file_name = os.path.basename(self.binary_path)
        file_md5_prefix = get_md5_prefix(self.binary_path)
        self.other_config[file_name] = f"{file_name}_{file_md5_prefix}"

        self.project_name = os.path.join(f"../", self.config['ResultDir']['lib_path'], f"{file_name}_{file_md5_prefix}")  if main_file else f"{file_name}_{file_md5_prefix}"  # check is mainfile or libs
        if not main_file:
            self.main_project_name = self.project_name
            self.main_file_name = file_name
            
        
        self.set_directory_map()

        
    def load_config(self, config_file):
        """
        Reads and parses the INI config file, returning a dictionary with configuration details.
        :param config_file: Path to the config file
        :return: Dictionary with the configuration
        """
        config = configparser.ConfigParser()
        config.read(config_file)
        
        # loaded_config = {}
        # for section in config.sections():
        #     loaded_config[section] = {}
        #     for key, value in config.items(section):
        #         loaded_config[section][key] = value.split(', ')
        
        return config
    
    def export_vulconfig_function(self):
        """
        Extract and return the list of dangerous functions defined in the 'VulFunction' section of the config.
        :return: Dictionary containing dangerous function names categorized by the key in the config.
        """
        # Check if 'VulFunction' section exists in the config
        if 'VulFunction' not in self.config:
            print("No 'VulFunction' section found in config.")
            return {}

        # Export dangerous functions as a dictionary where keys are the categories and values are lists of functions
        vul_functions = self.config['VulFunction']

        # Format the dangerous functions into a dictionary of arrays
        function_data = {}
        for category, functions in vul_functions.items():
            function_data[category] = functions.split(', ')

        return function_data

    def generate_scripts_config(self):
        scripts = {}
        for name, file in self.config["Script"].items():
            scripts[name] = os.path.join(GHIDRA_SCRIPT_ROOT_PATH, file)
        
        pass
    
    def load_vfuncParam(self):
        vparam = self.config['VulFunction']['param']
        vparam_json = json.loads(vparam)


    def set_directory_map(self):
        self.directory_map = {
            "elfParse" : os.path.join(self.config["ResultDir"]["root"] , self.device, self.project_name, self.config["ResultDir"]["elf_parse"]),
            "binary" : os.path.join(self.config["ResultDir"]["root"], self.device, self.project_name, self.config["ResultDir"]["iot_file"]),
            "ghidra" : os.path.join(self.config["ResultDir"]["root"], self.device, self.project_name, self.config["ResultDir"]["ghidra"]),
        }

        for directory in self.directory_map.values():
            ensure_directory_exists(directory)



IoTReaperConfig = Config()
# project path


if __name__ == "__main__":
    print(IoTReaperConfig.export_vulconfig_function())
    print(HOME)
    print(HEADLESS_GHIDRA)
    print(GHIDRA_SCRIPT)
    print(IoTReaperConfig.config["Script"])


    