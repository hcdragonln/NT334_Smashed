<?php

use Illuminate\Database\Seeder;
use App\User;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;


class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     *
     * @return void
     */
    public function run()
    {
        User::create(['name' => 'administrator', 'email' => 'administrator@gmail.com', 'password' => bcrypt('12345678'), 'created_at' => NOW()]);
        $this->call(UsersTableSeeder::class);
    }
}
