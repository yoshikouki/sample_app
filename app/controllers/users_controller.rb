class UsersController < ApplicationController
  
  before_action :logged_in_user,  only: [:edit, :update, :index, :destroy]
  before_action :correct_user,    only: [:edit, :update]
  before_action :admin_user,      only: [:destroy]
  
  def index
    @users = User.where(activated: true).paginate(page: params[:page])
  end
  
  def new
  end
  
  def show
    @user = User.find(params[:id])
    redirect_to root_url and return unless @user.activated?
  end
  
  def new
    @user = User.new
  end
  
  def create
    @user = User.new(user_params)
    if @user.save
      # ユーザーを有効化するメールを送信
      @user.send_activation_email
      # メッセージを作成
      flash[:info] = "Please check your email to activate your accout."
      redirect_to root_url
    else
      render 'new'
    end
  end
  
  def edit
    @user = User.find(params[:id])
  end
  
  def update
    @user = User.find(params[:id])
    if @user.update_attributes(user_params)
      # 更新成功した場合
      flash[:success] = "Profile updated!"
      redirect_to @user
    else
      # 更新が失敗した場合。入力値エラー等
      render 'edit'
    end
  end
  
  def destroy
    User.find(params[:id]).destroy
    flash[:success] = "User deleted"
    redirect_to users_path
  end
  
  private
  
    # マスアサインメントの脆弱性対策（Strong Parameters）
    def user_params
      params.require(:user).permit(:name,:email,:password,
                                   :password_confirmation)
    end
    
    # beforeアクション
    
    # ログイン済みのユーザーかどうかを確認
    def logged_in_user
      unless logged_in?
        store_location
        flash[:danger] = "Please log in."
        redirect_to login_url
      end
    end
    
    # 正しいユーザーかどうかの確認
    def correct_user
      @user = User.find(params[:id])
      redirect_to(root_url) unless current_user?(@user)
    end
    
    # 管理者かどうかの確認
    def admin_user
      redirect_to root_url unless current_user.admin?
    end
end
