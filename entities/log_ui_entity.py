# entities/log_ui_entity.py
from dataclasses import dataclass, field
from typing import Dict, Any, Union
from datetime import datetime
from enum import Enum
from infrastructure.log_ui_type import LogUIType


@dataclass
class LogUIEntity:
    __type: LogUIType
    __description: str
    __parameter: Union[str, Enum]
    __timestamp: datetime = field(init=False)

    def __post_init__(self):
        self.__timestamp = datetime.now()

    # --- properties ---
    @property
    def type(self) -> LogUIType:
        return self.__type

    @property
    def description(self) -> str:
        return self.__description

    @property
    def parameter(self) -> Union[str, Enum]:
        return self.__parameter

    @parameter.setter
    def parameter(self, value: Union[str, Enum]):
        if not isinstance(value, (str, Enum)):
            raise TypeError("parameter must be str or Enum")
        self.__parameter = value

    @property
    def timestamp(self) -> datetime:
        return self.__timestamp

    # --- export ---
    def to_dict(self) -> Dict[str, Any]:
        # analysis type (LogUIType Enum)
        if isinstance(self.type, LogUIType):
            type_out = self.type.name
        elif isinstance(self.type, Enum):
            type_out = self.type.name
        else:
            type_out = str(self.type)

        # analysis parameter (Enum or string)
        param = self.parameter
        if isinstance(param, Enum):
            param_out = param.name
        else:
            param_out = str(param)

        return {
            "type": type_out,
            "description": str(self.description),
            "parameter": param_out,
            "timestamp": self.timestamp,
        }
