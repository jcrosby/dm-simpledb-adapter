require File.expand_path(File.dirname(__FILE__)) + '/spec_helper'

describe "SimpleDbAdapter" do

  def insert_two_documents
    ['1', '2'].each do |id|
      doc = Document.new(@default_data.merge(:id => id, :uri => "/notes/#{id}"))
      @dm.db.put_attributes('cloudkit', doc.id, doc.attributes)
    end
  end

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

  it "raises an exception if a resource has no key"

  it "updates a document" do
    document = Document.create(@default_data)
    document.update_attributes(:uri => '/notes/777')
    new_document = Document.get(document.id)
    new_document.uri.should == '/notes/777'
  end

  it "updates many documents" # not sure if Document.all(:x => y).update!(:x => z) is the proper thing to do with DM

  it "caches on write"

  it "deletes a document" do
    doc = Document.create(@default_data.merge(:id => 'one'))
    Document.all(:id => 'one').size.should == 1
    doc.destroy
    @dm.db.query('cloudkit')[:items].size.should == 0
  end

  it "deletes many documents"

  it "deletes from the cache"

  it "gets a document by its key" do
    document = Document.new(@default_data.merge(:id => 'myid'))
    @dm.db.put_attributes('cloudkit', 'myitem', document.attributes)
    fetched_document = Document.get(document.id)
    fetched_document.id.should == document.id
    fetched_document.uri.should == '/notes/123'
  end

  it "finds a document using first" do
    insert_two_documents
    Document.first(:content => '{}').content.should == '{}'
  end

  it "returns nil for Resource#get if the id is not found" do
    Document.get('x').should be_nil
  end

  it "finds many documents using :eql" do
    insert_two_documents
    no_match = Document.new(@default_data.merge(:id => 3, :uri => "/notes/3", :content => '{x}'))
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

  it "finds using :gt"

  it "finds using :gte"

  it "finds using :lt"

  it "finds using :lte"

  it "finds using :not"

  it "finds using SimpleDB's concept of ':like"

  it "raises an exception when using not using SimpleDB's concept of :like"

  it "finds using :in"

  it "orders ascending on a field" do
    insert_two_documents
    Document.all(:order => [:uri.asc]).map{ |d| d.id }.should == ['1', '2']
  end

  it "orders descending on a field" do
    insert_two_documents
    Document.all(:order => [:id.desc]).map{ |d| d.id }.should == ['2', '1']
  end

  it "gets recent documents from the cache"

  describe "complying with AWS restrictions" do

    it "ensures domain names are 3-255 characters"

    it "limits to 100 domain names"

    it "limits attribute name/value pairs to 256 per item"

    it "limits attribute names to 1024 bytes"

    it "limits attribute value lengths to 1024 bytes" # should split over multiple values

    it "limits to 100 attributes per PUT operation"

    it "limits attributes per query to 256"

    it "limits query expressions to 10 predicates"

    it "limits unique attributes to 20 per select expression"

    it "limits comparisons to 20 per select expression"

    it "limits the response size for QueryWithAttributes and Select to 1MB"

    it "limits 'order by' to one expression" do
      lambda do
        Document.all(:order => [:id.desc, :uri.desc])
      end.should raise_error(NotImplementedError)
    end
  end
end
