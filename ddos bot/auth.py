from datetime import date, datetime, timedelta
import json
from json import JSONEncoder
import dateutil.parser

file = "./authd_users.json"

def expire_time_helper(start_time, days=0, seconds=0, microseconds=0, milliseconds=0, minutes=0, hours=0, weeks=0):
  return start_time + timedelta(days, seconds, microseconds, milliseconds, minutes, hours, weeks)

def add_user(user_id: str, **expire_time):
  data = _read_data()

  start_time = datetime.now()

  data[user_id] = { 'active'      : True,
                    'start_time'  : start_time,
                    'expire_time' : expire_time_helper(start_time, **expire_time)
                  }

  _write_data(data)

def explicit_expire_user(user_id: str):
  """Expire a user id now"""
  data = _read_data()

  expired_users = []

  for k,v in data.items():
    if k == user_id and v['active']:
      data[k]['active'] = False
      expired_users.append(k)

  if len(expired_users):
    _write_data(data)

  return expired_users
  
def expire():
  """Check for and expire newly expired user.
  Return any users ID's of recently expired users."""

  data = _read_data()

  expired_users = []

  for k,v in data.items(): 
    if v['active'] and datetime.now() >= v['expire_time']:
      data[k]['active'] = False
      expired_users.append(k)

  if len(expired_users):
    _write_data(data)

  return expired_users

def time_remaning(user_id: str):
  data = _read_data()

  result = data.get(user_id, {'active': None, 'expire_time': None})

  if result['active']:
    return result['expire_time']

  return None

def _read_data():
  with open(file, 'r') as f:
    return json.loads(f.read() or '{}', object_hook=_DecodeDateTime)

def _write_data(data):
  with open(file, 'w') as f:
    f.write(json.dumps(data, cls=_DateTimeEncoder))

# datetime serialization help from  https://pynative.com/python-serialize-datetime-into-json/

class _DateTimeEncoder(JSONEncoder):
  def default(self, obj):
    if isinstance(obj, (date, datetime)):
      return obj.isoformat()

def _DecodeDateTime(empDict):
  if 'start_time' in empDict:
    empDict["start_time"] = dateutil.parser.parse(empDict["start_time"])
  if 'expire_time' in empDict:
    empDict["expire_time"] = dateutil.parser.parse(empDict["expire_time"])
  
  return empDict