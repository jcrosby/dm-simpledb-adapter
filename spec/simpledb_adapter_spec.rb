require File.expand_path(File.dirname(__FILE__)) + '/spec_helper'

describe "SimpleDbAdapter" do

  before(:each) do
    DataMapper.auto_migrate!
  end

  it "stores a document" do
    document = Document.create(
      :uri => '/notes',
      :content => '{}')
    Document.all.count.should == 1
  end

  it "stores many documents"

  it "updates a document"

  it "updates many documents"

  it "deletes a document"

  it "deletes many documents"

  it "gets a document"

  it "gets many documents"
end
