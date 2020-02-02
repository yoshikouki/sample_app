class UsersController < ApplicationController
  
  before_action :logged_in_user,  only: [:edit, :update, :index]
  before_action :correct_user,    only: [:edit, :update]
  
  def index
    @users = User.paginate(page: params[:page])
  end
  
  def new
  end
  
  def show
    @user = User.find(params[:id])
  end
  
  def new
    @user = User.new
  end
  
  def create
    @user = User.new(user_params)
    if @user.save
      # 作成したユーザーでログイン
      log_in @user
      # ユーザー登録が完了したメッセージを作成
      flash[:success] = "Welcome to the Sample App!"
      redirect_to user_url(@user)
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
  
  private
  
    # マスアサインメントの脆弱性対策（Strong Parameters）
    def user_params
      params.require(:user).permit(:name,:email,:password,:password_confirmation)
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
end
