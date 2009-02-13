require File.expand_path(File.dirname(__FILE__)) + '/../lib/simpledb_adapter'

class Document
  include DataMapper::Resource

  # :nullable => true appears to be required for String keys, due to DM's
  # expectation that the read_one call will include a valid key even for items
  # that are not found. This happens before the #create method has a chance to
  # set the key.
  property :id,          String, :key => true, :nullable => true
  property :uri,         String, :length => 255, :unique => true
  property :remote_user, String, :length => 255
  property :content,     Text
  property :deleted,     Boolean, :default => false
end

class View
  include DataMapper::Resource

  property :id,     String, :key => true, :nullable => true
  property :uri,    String, :length => 255, :unique => true
  property :color,  Text
  property :weight, Text
end
