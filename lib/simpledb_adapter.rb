require 'rubygems'
require 'dm-core'
require 'dm-validations'
require 'right_aws'

module DataMapper
  module Adapters

    # A SimpleDB adapter for DataMapper built on the Rightscale gem.
    class SimpleDbAdapter < AbstractAdapter

      def initialize(name, uri_or_options)
        super
        @db = RightAws::SdbInterface.new(
          @uri[:access_key], @uri[:secret_key], @uri[:params]={})
      end

      def create(resources)
        created = 0
        resources.each do |resource|
        end
        created
      end

      def read_one(query)
      end

      def read_many(query)
      end

      def update(attributes, query)
      end

      def delete(query)
      end

      protected

      module Migration
        def storage_exists?(storage_name)
        end

        def create_model_storage(repository, model)
        end

        def destroy_model_storage(repository, model)
        end
      end

      include Migration
    end

    SimpledbAdapter = SimpleDbAdapter
  end
end
