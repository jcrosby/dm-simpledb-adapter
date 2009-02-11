require File.expand_path(File.dirname(__FILE__)) + '/spec_helper'

describe "SimpleDbAdapter" do

  before(:each) do
    DataMapper.setup(:default, {
      :server     => 'localhost',
      :adapter    => 'simpledb',
      :access_key => 'fake',
      :secret_key => 'fake',
      :port       => '8080',
      :protocol   => 'http',
      :domain     => 'cloudkit',
      :logger     => Logger.new('test.log')})
    DataMapper.auto_migrate!
    @dm = DataMapper.repository(:default).adapter
  end

  it "creates its storage" do
    @dm.db.list_domains[:domains].should == ['cloudkit']
  end

  it "uses a default domain name if none is provided" do
    DataMapper.setup(:default, {
      :server     => 'localhost',
      :adapter    => 'simpledb',
      :access_key => 'fake',
      :secret_key => 'fake',
      :port       => '8080',
      :protocol   => 'http',
      :logger     => Logger.new('test.log')})
    DataMapper.auto_migrate!
    dm = DataMapper.repository(:default).adapter
    dm.db.list_domains[:domains].should == ['dm-simpledb']
  end

  it "knows if its storage exists"

  it "destroys its storage" # including document.id keys

  it "stores a document" do
    Document.create(
      :uri     => '/notes/123',
      :content => '{}')
    @dm.db.query('cloudkit')[:items].size.should == 1
  end

  it "sets the document's id" do
    document = Document.create(
      :uri     => '/notes/123',
      :content => '{}')
    document.id.should_not be_nil
    document.id.should_not == ''
  end

  it "stores a document with a content attribute value larger than 1024K"

  it "updates a document" do
    pending "implement"
    document = Document.create(
      :uri     => '/notes/123',
      :content => '{}')
    document.update_attributes(:uri => '/notes/777')
    document.reload.uri.should == '/notes/777'
  end

  it "updates many documents"

  it "caches on write"

  it "deletes a document"

  it "deletes many documents"

  it "deletes from the cache"

  it "gets a document"

  it "gets many documents"

  it "gets recent documents from the cache"
end
