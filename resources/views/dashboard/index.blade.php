@extends('layout')

@section('content')
    <div class="page-header">
        <h1>Dashboard</h1>
    </div>

    <h2>Entity Counts</h2>
    <div class="col-md-12">
        <div class="col-md-6">
            <h3>Entity Counts</h3>
            <ul class="list-group">
                <li class="list-group-item">Pools: {{ $counts['pool'] }}</li>
                <li class="list-group-item">Cryptos: {{ $counts['crypto'] }}</li>
                <li class="list-group-item">Servers: {{ $counts['server'] }}</li>
                <li class="list-group-item">Ports: {{ $counts['port'] }}</li>
                <li class="list-group-item">Addresses: {{ $counts['address'] }}</li>
                <li class="list-group-item">Probes: {{ $counts['probes'] }}</li>
                <li class="list-group-item">History: {{ $counts['history'] }}</li>
            </ul>
        </div>
        <div class="col-md-6">
            <!-- Render the summary counts chart -->
            <canvas id="summaryCountsChart"></canvas>
        </div>
        <div class="clearfix"></div>
        <hr>
    </div>

    <h2>Currency Usage</h2>
    <div class="col-md-12">
        <div class="col-md-6">
            <!-- Currency Usage Pie Chart -->
            <canvas id="summaryCurrenciesChart"></canvas>
        </div>
        <div class="col-md-6">
            <h3>Currency Usage Details</h3>
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Currency</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach($used_currencies as $currency)
                        <tr>
                            <td class="col-md-4">
                                <a href="{{ url('crypto', $currency->crypto_id) }}">{{ $currency->name }}</a>
                            </td>
                            <td class="col-md-2">
                                {{ $currency->count }}
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
        <div class="clearfix"></div>
        <hr>
    </div>

    <h2>Pools</h2>
    <div class="col-md-12">
        <div class="col-md-6">
            <!-- Pools Multi Bar Chart -->
            <canvas id="summaryPoolsChart"></canvas>
        </div>
        <div class="col-md-6">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Pool Name</th>
                        <th>FQDN Count</th>
                        <th>IP Count</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach($pool_stats as $stat)
                        <tr>
                            <td class="col-md-4">
                                <a href="{{ url('pool', $stat[0]->id) }}">{{ $stat[0]->name }}</a>
                            </td>
                            <td class="col-md-1">
                                {{ $stat[0]->fqdn_count }}
                            </td>
                            <td class="col-md-1">
                                {{ $stat[1]->addr_count }}
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    </div>
@endsection

@section('footer')
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.9.4/Chart.min.js"></script>

<script>
    window.onload = function() {
        // Summary Counts Chart
        var ctxCounts = document.getElementById('summaryCountsChart').getContext('2d');
        new Chart(ctxCounts, {
            type: 'bar',
            data: {
                labels: {!! json_encode(['Pools', 'Cryptos', 'Servers', 'Ports', 'Addresses']) !!},
                datasets: [{
                    label: 'Count',
                    data: {!! json_encode([$counts['pool'], $counts['crypto'], $counts['server'], $counts['port'], $counts['address']]) !!},
                    backgroundColor: ['#64B5F6', '#2196F3', '#1976D2', '#64B5F6', '#2196F3']
                }]
            },
            options: {
                responsive: true,
                title: {
                    display: true,
                    text: 'Entity Counts'
                }
            }
        });

        // Currency Usage Pie Chart
        var ctxCurrencies = document.getElementById('summaryCurrenciesChart').getContext('2d');
        new Chart(ctxCurrencies, {
            type: 'pie',
            data: {
                labels: {!! json_encode($currency_labels) !!},
                datasets: [{
                    label: 'Currencies',
                    data: {!! json_encode($currency_counts) !!},
                    backgroundColor: ['#64B5F6', '#2196F3', '#1976D2', '#64B5F6', '#2196F3']
                }]
            },
            options: {
                responsive: true,
                title: {
                    display: true,
                    text: 'Currency Usage'
                }
            }
        });

        // Pools Multi Bar Chart (FQDN and IP Counts)
        var ctxPools = document.getElementById('summaryPoolsChart').getContext('2d');
        new Chart(ctxPools, {
            type: 'bar',
            data: {
                labels: {!! json_encode($pool_labels) !!},
                datasets: [
                    {
                        label: 'FQDN Count',
                        data: {!! json_encode($pool_fqdn_counts) !!},
                        backgroundColor: '#64B5F6'
                    },
                    {
                        label: 'IP Count',
                        data: {!! json_encode($pool_addr_counts) !!},
                        backgroundColor: '#2196F3'
                    }
                ]
            },
            options: {
                responsive: true,
                title: {
                    display: true,
                    text: 'Pools (FQDN and IP Counts)'
                }
            }
        });
    };
</script>
@endsection
