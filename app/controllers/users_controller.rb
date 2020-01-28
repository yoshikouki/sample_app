class UsersController < ApplicationController
  def new
  end
  
  def show
    @user = User.find( params[:id] )
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
  
  private
    # StrongParam
    def user_params
      params.require(:user).permit(:name,:email,:password,:password_confirmation)
    end
end
