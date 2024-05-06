<?php

namespace App\Http\Controllers;

use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use PhpParser\Node\Stmt\TryCatch;

class AuthController extends Controller
{
    //

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login' , 'refresh']]);
    }

    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $refreshToken = $this ->createRefreshToken();

        return $this->respondWithToken($token, $refreshToken);
    }

    public function profile()
    {
        try {
            return response()->json(auth('api')->user());
        } catch (Exception $exception){
            return response()->json(['error' => 'Unauthorized'], 401);
        }

    }

    public function logout()
    {
        auth('api')->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    public function refresh()
    {
        $refreshToken = request() -> refresh_token;
        try {
            $decode = JWTAuth::getJWTProvider()->decode($refreshToken);
            $user = User::find($decode['user_id']);
            if(!$user){
                return response()->json(['error' => 'User Not Found'], 404);
            }
            auth()->invalidate();
            $token = auth('api')->login($user);
            $refreshToken = $this -> createRefreshToken();

            return $this->respondWithToken($token, $refreshToken);
        }catch( Exception $exception) {
            return response()->json(['error' => 'Refresh Token Invalid'], 500);
        }

    }


    protected function respondWithToken($token, $refreshToken)
    {
        return response()->json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }

    public function createRefreshToken(){
        $data = [
            'user_id' => auth('api')->user()->id,
            'random' => rand().time(),
            'exp' => time() + config('jtw.refresh_ttl')
        ];

        $refreshToken = JWTAuth::getJWTProvider()->encode($data);
        return $refreshToken;
    }
}
