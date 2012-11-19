class User < ActiveRecord::Base
  attr_accessor :password_confirmation
  attr_accessible :email, :password, :password_confirmation

  validates_uniqueness_of :email


  before_create :encrypt_password

  def authenticate(submitted_password)
    self.hash_password?(submitted_password)
  end

  def hash_password?(submitted_password)
    self.encrypted_password == encrypt(submitted_password)
  end

  private

  def encrypt_password
    if self.new_record?
      self.salt = make_salt
      self.encrypted_password = encrypt(self.password) unless self.password.blank?
    end
  end

  def make_salt
    secure_hash("#{Time.now.sec}--#{@password}")
  end

  def encrypt(password)
    secure_hash("#{self.salt}--#{password}--car")
  end

  def secure_hash(string)
    Digest::SHA2.hexdigest(string)
  end
end
