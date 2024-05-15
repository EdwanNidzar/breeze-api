<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use Illuminate\Database\Eloquent\Casts\Json;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Exception;
use Illuminate\Validation\ValidationException;

class AuthenticatedSessionController extends Controller
{
    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request): JsonResponse
    {
        try {
            // Authenticate the user with the provided credentials
            $request->authenticate();

            // Retrieve the authenticated user
            $user = $request->user();

            // Use a transaction to ensure both operations succeed or fail together
            DB::beginTransaction();

            // Revoke all current tokens for the user
            $user->tokens()->delete();

            // Create a new token for the user
            $token = $user->createToken('auth_token');

            DB::commit();

            return response()->json([
                'token' => $token->plainTextToken,
                'token_type' => 'Bearer',
                'user' => $user,
            ]);
        } catch (ValidationException $e) {
            // Specific handling for validation exceptions
            return response()->json([
                'message' => 'Authentication failed',
                'errors' => $e->errors(),
            ], 422);
        } catch (Exception $e) {
            DB::rollBack();
            
            // General error handling
            return response()->json([
                'message' => 'Authentication failed',
                'error' => $e->getMessage()
            ], 401);
        }
    }


    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): JsonResponse
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return response()->json(['message' => 'Session destroyed successfully']);
    }
}
