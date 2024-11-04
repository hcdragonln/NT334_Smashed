<?php

namespace App\Http\Controllers;

use DB;
use Illuminate\Http\Request;
use ConsoleTVs\Charts\Classes\Chartjs\Chart;

class DashboardController extends Controller
{
    public function index()
    {
        // Count different entities
        $counts['pool'] = DB::table('pools')->count();
        $counts['crypto'] = DB::table('cryptos')->count();
        $counts['server'] = DB::table('servers')->count();
        $counts['port'] = DB::table('ports')->select('number')->get()->unique()->sort()->count();
        $counts['address'] = DB::table('addresses')->count();
        $counts['probes'] = DB::table('miningProperties')->count();
        $counts['history'] = DB::table('history')->count();

        // Summary Counts Chart
        $charts['summary_counts_chart'] = new Chart();
        $charts['summary_counts_chart']->title('Count')
            ->type('bar')
            ->options([
                'colors' => ['#64B5F6', '#2196F3', '#1976D2'],
                'elementLabel' => 'Total'
            ])
            ->labels(['Pools', 'Cryptos', 'Servers', 'Ports', 'Addresses']);
        
        $charts['summary_counts_chart']->dataset('Count', 'bar', [
            $counts['pool'], $counts['crypto'], $counts['server'], $counts['port'], $counts['address']
        ]);

        // Currency Usage Pie Chart
        $used_currencies = DB::table('ports')
            ->select('ports.crypto_id', 'cryptos.name', DB::raw('count(*) as count'))
            ->join('cryptos', 'ports.crypto_id', '=', 'cryptos.id')
            ->groupBy('crypto_id')
            ->get()->toArray();

        $currency_labels = [];
        $currency_counts = [];
        foreach ($used_currencies as $currency) {
            $currency_labels[] = $currency->name;
            $currency_counts[] = $currency->count;
        }

        $charts['summary_currencies_chart'] = new Chart();
        $charts['summary_currencies_chart']->title('Currencies')
            ->type('pie')
            ->options([
                'colors' => ['#64B5F6', '#2196F3', '#1976D2']
            ])
            ->labels($currency_labels)
            ->dataset('Currencies', 'pie', $currency_counts);

        // Pools Multi Bar Chart (FQDN and IP Counts)
        $tmp1 = DB::table('pools')
            ->select('pools.id', 'pools.name', DB::raw('count(servers.fqdn) as fqdn_count'))
            ->join('servers', 'pools.id', '=', 'servers.pool_id')
            ->groupBy('pools.id')
            ->get();

        $tmp2 = DB::table('pools')
            ->select('pools.id', DB::raw('count(addresses.address) as addr_count'))
            ->join('servers', 'pools.id', '=', 'servers.pool_id')
            ->join('addresses', 'servers.id', '=', 'addresses.server_id')
            ->groupBy('pools.id')
            ->get();

        $pool_stats = $tmp1->zip($tmp2)->toArray();
        $pool_labels = [];
        $pool_fqdn_counts = [];
        $pool_addr_counts = [];
        
        foreach ($pool_stats as $stat) {
            $pool_fqdn_counts[] = $stat[0]->fqdn_count;
            $pool_addr_counts[] = $stat[1]->addr_count;
            $pool_labels[] = $stat[0]->name;
        }

        $charts['summary_pools_chart'] = new Chart();
        $charts['summary_pools_chart']->title('Pools')
            ->type('bar')
            ->options([
                'colors' => ['#64B5F6', '#2196F3']
            ])
            ->labels($pool_labels);

        // Adding each dataset separately
        $charts['summary_pools_chart']->dataset('FQDN', 'bar', $pool_fqdn_counts);
        $charts['summary_pools_chart']->dataset('IP', 'bar', $pool_addr_counts);

        return view('dashboard.index')
            ->with('charts', $charts) // Pass the $charts array
            ->with('counts', $counts)
            ->with('used_currencies', $used_currencies)
            ->with('pool_stats', $pool_stats)
            ->with('currency_labels', $currency_labels) // Pass currency_labels to the view
            ->with('pool_labels', $pool_labels)
            ->with('pool_fqdn_counts', $pool_fqdn_counts)
            ->with('pool_addr_counts', $pool_addr_counts)
            ->with('currency_counts', $currency_counts); // Pass currency_counts to the view
    }
}
