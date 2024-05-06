<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $user = new User();
        $user -> name = 'User 1';
        $user -> password = Hash::make('123456');
        $user -> email = 'btthanh11@gmail.com';
        $user -> save();
    }
}
