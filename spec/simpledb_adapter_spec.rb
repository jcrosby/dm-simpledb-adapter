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
    @default_data = {
      :uri         => '/notes/123',
      :content     => '{}',
      :remote_user => 'jethro'}
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
    document = Document.create(@default_data)
    @dm.db.query('cloudkit')[:items].size.should == 1
  end

  it "sets the document's key if not provided" do
    document = Document.create(@default_data)
    document.id.should_not be_nil
    document.id.should_not == ''
  end

  it "allows a custom key on create" do
    document = Document.create(@default_data.merge(:id => 'x'))
    document.id.should == 'x'
  end

  it "stores a document with a content attribute value larger than 1024K"

  it "updates a document" do
    document = Document.create(@default_data)
    document.update_attributes(:uri => '/notes/777')
    new_document = Document.get(document.id)
    new_document.uri.should == '/notes/777'
  end

  it "updates many documents"

  it "caches on write"

  it "deletes a document" do
    doc = Document.create(@default_data.merge(:id => 'one'))
    Document.all(:id => 'one').size.should == 1
    doc.destroy
    @dm.db.query('cloudkit')[:items].size.should == 0
  end

  it "deletes many documents"

  it "deletes from the cache"

  it "gets a document" do
    document = Document.new(@default_data.merge(:id => 'myid'))
    @dm.db.put_attributes('cloudkit', 'myitem', document.attributes)
    fetched_document = Document.get(document.id)
    fetched_document.id.should == document.id
    fetched_document.uri.should == '/notes/123'
  end

  it "returns nil for Resource#get if the id is not found"

  it "gets many documents" do
    ['1', '2'].each do |id|
      doc = Document.new(@default_data.merge(:id => id))
      @dm.db.put_attributes('cloudkit', doc.id, doc.attributes)
    end
    no_match = Document.new(@default_data.merge(:id => 3, :content => '{x}'))
    @dm.db.put_attributes('cloudkit', no_match.id, no_match.attributes)
    documents = Document.all(:content => '{}')
    documents.size.should == 2
    documents.map { |d| ['1', '2'].include?(d.id).should be_true }
  end

  it "returns an empty array when no matches are found" do
    doc = Document.new(@default_data.merge(:id => 'one'))
    @dm.db.put_attributes('cloudkit', doc.id, doc.attributes)
    Document.all(:id => 'fail').size.should == 0
  end

  it "gets recent documents from the cache"
end
