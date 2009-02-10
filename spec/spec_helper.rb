require File.expand_path(File.dirname(__FILE__)) + '/../lib/simpledb_adapter'

access_key = 'fake'
secret_key = 'fake'

DataMapper.setup(:default, {
  :host       => 'localhost',
  :port       => '8080',
  :adapter    => 'simpledb',
  :access_key => access_key,
  :secret_key => secret_key,
  :domain     => 'documents'
})

class Document
  include DataMapper::Resource

  property :id,                   Serial
  property :uri,                  String, :length => 255, :unique => true
  property :remote_user,          String, :length => 255
  property :content,              Text
  property :deleted,              Boolean, :default => false
end
