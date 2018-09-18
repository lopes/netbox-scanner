# postgres=# CREATE DATABASE nbscan;
# CREATE DATABASE
# postgres=# CREATE USER nbscan WITH PASSWORD 'abc123';
# CREATE ROLE
# postgres=# GRANT ALL PRIVILEGES ON DATABASE nbscan TO nbscan;
# GRANT
# postgres=# \q
##


from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base

from config import DATABASE


base = declarative_base()


class Host(base):
    __tablename__ = 'Hosts'
    id = Column(Integer, primary_key=True)
    date = Column(DateTime, nullable=False)
    network = Column(String(120), nullable=False)
    address = Column(String(100), nullable=False)
    name = Column(String(255))
    cpe = Column(String(255))

    def __init__(self, d, net, a, n, c):
        self.date = d
        self.network = net
        self.address = a
        self.name = n
        self.cpe = c

    def __repr__(self):
        return '<Host: address={}, network={}, name={}>'.format(self.address, 
            self.network, self.name)


engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(DATABASE['USER'], 
    DATABASE['PASSWORD'], DATABASE['HOST'], DATABASE['PORT'], 
    DATABASE['NAME']))
base.metadata.create_all(engine)
