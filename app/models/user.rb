class User < ApplicationRecord
  
  #仮想トークン属性
  attr_accessor :remember_token, :activation_token, :reset_token
  
  before_save :downcase_email
  before_create :create_activation_digest
  
  # バリデーション（正規化も含む）
  validates :name,      presence: true, 
                        length: { maximum: 50 }
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
  validates :email,     presence: true, 
                        length: { maximum: 255 },
                        format: { with: VALID_EMAIL_REGEX },
                        uniqueness: { case_sensitive: false }
                    
  #安全なパスワードの生成と、仮想パスワード属性の作成。
  has_secure_password
  validates :password,  presence: true, 
                        length: { minimum: 6 },
                        allow_nil: true
  
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
  def authenticated?(attribute, token)
    digest = send("#{attribute}_digest")
    return false if digest.nil?
    BCrypt::Password.new(digest).is_password?(token)
  end
  
  # 永続セッションを破棄。ログアウト時
  def forget
    update_attribute(:remember_digest, nil)
  end
  
  # アカウントを有効化
  def activate
    update_columns(activated: true, activated_at: Time.zone.now)
  end
  
  # 有効化用のメールを送信
  def send_activation_email
    UserMailer.account_activation(self).deliver_now
  end
  
  # パスワード再設定の属性を設定
  def create_reset_digest
    self.reset_token = User.new_token
    update_columns( reset_digest: User.digest(reset_token), 
                    reset_sent_at: Time.zone.now)
  end
  
  # パスワード再設定のメールを送信
  def send_password_reset_email
    UserMailer.password_reset(self).deliver_now
  end
  
  # パスワード再設定の有効期限が切れている場合はtrue
  def password_reset_expired?
    reset_sent_at < 2.hours.ago
  end
  
  private
    
    # emailを全て小文字化
    def downcase_email
      self.email.downcase!
    end
    
    # 有効化トークンとダイジェストを作成及び代入
    def create_activation_digest
      self.activation_token  = User.new_token
      self.activation_digest = User.digest(activation_token)
    end
end