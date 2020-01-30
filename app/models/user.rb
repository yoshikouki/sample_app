class User < ApplicationRecord
  
  #仮想トークン属性。
  attr_accessor :remember_token
  
  before_save { email.downcase! }
  # before_save { self.email = email.downcase }
  validates :name,  presence: true, length: { maximum: 50 }
  
  # emailのバリデーションと正規化（前文は正規化の定数宣言）
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
  validates :email, presence: true, length: { maximum: 255 },
                    format: { with: VALID_EMAIL_REGEX },
                    uniqueness: { case_sensitive: false }
                    
  #安全なパスワードの生成と、仮想パスワード属性の作成。
  has_secure_password
  validates :password, presence: true, length: { minimum: 6 }
  
  # 渡された文字列をハッシュして値を返す
  def self.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end
  
  # ランダムなトークンを返す。cookiesに使用。
  def self.new_token
    SecureRandom.urlsafe_base64
  end
  
  # 永続セッションのためにユーザーをデータベースに記憶
  def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end
  
  # 渡されたトークンがダイジェストと一致したらtrue
  def authenticated?(remember_token)
    return false if remember_digest.nil?
    BCrypt::Password.new(remember_digest).is_password?(remember_token)
  end
  
  # 永続セッションを破棄。ログアウト時
  def forget
    update_attribute(:remember_digest, nil)
  end
end