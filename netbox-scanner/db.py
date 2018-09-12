# postgres=# CREATE DATABASE nbscanner;
# CREATE DATABASE
# postgres=# CREATE USER nbscanner WITH PASSWORD 'abc123';
# CREATE ROLE
# postgres=# GRANT ALL PRIVILEGES ON DATABASE nbscanner TO nbscanner;
# GRANT
# postgres=# \q
#
#
#
# https://www.pythoncentral.io/introductory-tutorial-python-sqlalchemy/
# http://www.rmunn.com/sqlalchemy-tutorial/tutorial.html



from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base


class Host(db.Model):
    __tablename__ = 'Hosts'
    id = self.con.Column(self.con.Integer, primary_key=True)
    date = self.con.Column(self.con.DateTime, nullable=False)
    session = self.con.Column(self.con.String(self.session_length), nullable=False)
    address = self.con.Column(self.con.String(100), nullable=False)
    name = self.con.Column(self.con.String(255))
    mac = self.con.Column(self.con.String(17))
    vendor = self.con.Column(self.con.String(100))
    osvendor = self.con.Column(self.con.String(100))
    osfamily = self.con.Column(self.con.String(100))
    cpe = self.con.Column(self.con.String(255))
    description = self.con.Column(self.con.String(100))

    def __init__(d, s, a, n, m, v, ov, of, c, desc):
        self.date = d
        self.session = s
        self.address = a
        self.name = n
        self.mac = m
        self.vendor = v
        self.osvendor = ov
        self.osfamily = of
        self.cpe = c
        self.description = desc

    def __repr__(self):
        return 'Host(addr={}, date={}, name={})'.format(self.address,
            self.date, self.name)


base = declarative_base()
engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(pguser,pgpass,pghost,pgport,pgdb))
base.metadata.create_all(engine)
