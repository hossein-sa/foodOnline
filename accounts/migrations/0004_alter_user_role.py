# Generated by Django 5.1.1 on 2024-10-10 12:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_userprofile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.PositiveSmallIntegerField(blank=True, choices=[(1, 'Vendor'), (2, 'Customer')], null=True),
        ),
    ]
