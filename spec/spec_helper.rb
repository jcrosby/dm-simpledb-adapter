require File.expand_path(File.dirname(__FILE__)) + '/../lib/simpledb_adapter'

class Document
  include DataMapper::Resource

  property :id,          Serial
  property :uri,         String, :length => 255, :unique => true
  property :remote_user, String, :length => 255
  property :content,     Text
  property :deleted,     Boolean, :default => false
end

class View
  include DataMapper::Resource

  property :id,     Serial
  property :uri,    String, :length => 255, :unique => true
  property :color,  Text
  property :weight, Text
end
